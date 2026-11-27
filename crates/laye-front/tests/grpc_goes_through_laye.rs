#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "because laye is HTTP/1 only."
// "that sounds like a problem"

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::{HeaderMap, Request, Response, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use laye_front::{Config, jwt};
use tokio::net::TcpListener;

const PUBLIC: &str = "https://api.q.example";
const QNTX_DID: &str = "did:key:z6MkqntxNodeStandsHere";

/// A gRPC message frame: uncompressed, its length, its bytes.
const ASKED: &[u8] = b"\x00\x00\x00\x00\x03ask";
const ANSWERED: &[u8] = b"\x00\x00\x00\x00\x06answer";

#[derive(Clone, Debug)]
struct Arrived {
    version: Version,
    path: String,
    authorization: String,
    body: Vec<u8>,
}

/// A QNTX that takes HTTP/2 without TLS only, as gRPC arrives at it, and
/// answers with a message and gRPC's status in trailers.
async fn qntx_at(
    addr: SocketAddr,
    arrived: Arc<Mutex<Vec<Arrived>>>,
) -> tokio::task::JoinHandle<()> {
    let listener = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let arrived = arrived.clone();
            tokio::spawn(async move {
                let service =
                    hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        let arrived = arrived.clone();
                        async move {
                            let version = req.version();
                            let path = req.uri().path().to_string();
                            let authorization = req
                                .headers()
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or_default()
                                .to_string();
                            let body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
                            arrived.lock().unwrap().push(Arrived {
                                version,
                                path,
                                authorization,
                                body,
                            });
                            let mut trailers = HeaderMap::new();
                            trailers.insert("grpc-status", "0".parse().unwrap());
                            let frames = futures::stream::iter(vec![
                                Ok::<_, Infallible>(Frame::data(Bytes::from_static(ANSWERED))),
                                Ok(Frame::trailers(trailers)),
                            ]);
                            let mut resp = Response::new(StreamBody::new(frames));
                            resp.headers_mut()
                                .insert("content-type", "application/grpc".parse().unwrap());
                            // grpc-go declares its trailers, as HTTP/1.1 needs
                            // before it carries them.
                            resp.headers_mut()
                                .insert("trailer", "Grpc-Status".parse().unwrap());
                            Ok::<_, Infallible>(resp)
                        }
                    });
                if let Err(e) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    eprintln!("the QNTX in this test ended a connection: {e}");
                }
            });
        }
    })
}

async fn free_addr() -> SocketAddr {
    let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
    held.local_addr().unwrap()
}

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("laye-grpc-{name}-{}", std::process::id()));
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn config(qntx: SocketAddr, dir: &std::path::Path) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        qntx: format!("http://{qntx}"),
        qntx_did: QNTX_DID.into(),
        public_origins: vec![PUBLIC.into()],
        held_at: dir.join("held.jsonl"),
        root_identities: Vec::new(),
        binding_signers: Vec::new(),
        issuer: "https://laye.example".into(),
        nodes: Vec::new(),
        invitations_at: dir.join("invitations.jsonl"),
        ceremony_at: "https://node.example".into(),
        names: None,
        passkeys: None,
        web: None,
        apns: None,
        pack_nodes: Vec::new(),
        governed: None,
    }
}

fn signed(session: &laye_me::Keypair) -> String {
    let did = laye_peer::did_of(session).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = jwt::sign(
        session,
        &jwt::Claims {
            iss: did.clone(),
            sub: did,
            aud: vec![PUBLIC.into()],
            exp: now + 60,
            jti: jwt::fresh_jti(),
            ..Default::default()
        },
    )
    .unwrap();
    format!("Signed {token}")
}

/// A gRPC call to laye, over HTTP/2 without TLS: its status, headers, body
/// and trailers.
async fn call(
    front: SocketAddr,
    authorization: &str,
) -> (u16, HeaderMap, Vec<u8>, Option<HeaderMap>) {
    let stream = tokio::net::TcpStream::connect(front).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(conn);
    let req = Request::post("http://api.q.example/lf.a2a.v1.A2AService/SendMessage")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("authorization", authorization)
        .body(Full::new(Bytes::from_static(ASKED)))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let (parts, body) = resp.into_parts();
    let collected = body.collect().await.unwrap();
    let trailers = collected.trailers().cloned();
    (
        status,
        parts.headers,
        collected.to_bytes().to_vec(),
        trailers,
    )
}

/// A gRPC call reaches QNTX in HTTP/2, told by laye whose it is, and QNTX's
/// answer comes back with its trailers.
#[tokio::test(flavor = "multi_thread")]
async fn a_grpc_call_goes_through_laye() {
    let arrived = Arc::new(Mutex::new(Vec::new()));
    let qntx = free_addr().await;
    let _qntx = qntx_at(qntx, arrived.clone()).await;
    let laye_key = laye_me::fresh();
    let (front, _run) = laye_front::start(config(qntx, &dir("through")), laye_key.clone())
        .await
        .unwrap();

    let session = laye_me::fresh();
    let (status, _, body, trailers) = call(front.addr, &signed(&session)).await;
    assert_eq!(status, 200);
    assert_eq!(body, ANSWERED);
    assert_eq!(trailers.unwrap().get("grpc-status").unwrap(), "0");

    let got = arrived.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].version, Version::HTTP_2);
    assert_eq!(got[0].path, "/lf.a2a.v1.A2AService/SendMessage");
    assert_eq!(got[0].body, ASKED);
    let claims = jwt::read(got[0].authorization.strip_prefix("Signed ").unwrap()).unwrap();
    assert_eq!(claims.iss, laye_peer::did_of(&laye_key).unwrap());
    assert_eq!(claims.sub, laye_peer::did_of(&session).unwrap());
}

/// A front door that ended TLS hands gRPC on in HTTP/1.1, as Caddy does;
/// it reaches QNTX in HTTP/2 all the same, and its trailers come back.
#[tokio::test(flavor = "multi_thread")]
async fn a_grpc_call_handed_on_in_http1_reaches_qntx_in_http2() {
    let arrived = Arc::new(Mutex::new(Vec::new()));
    let qntx = free_addr().await;
    let _qntx = qntx_at(qntx, arrived.clone()).await;
    let (front, _run) = laye_front::start(config(qntx, &dir("http1")), laye_me::fresh())
        .await
        .unwrap();

    let stream = tokio::net::TcpStream::connect(front.addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::post("/lf.a2a.v1.A2AService/SendMessage")
        .header("host", "api.q.example")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("authorization", signed(&laye_me::fresh()))
        .body(Full::new(Bytes::from_static(ASKED)))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let collected = resp.into_body().collect().await.unwrap();
    assert_eq!(
        collected.trailers().unwrap().get("grpc-status").unwrap(),
        "0"
    );
    assert_eq!(collected.to_bytes().as_ref(), ANSWERED);

    let got = arrived.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].version, Version::HTTP_2);
    assert_eq!(got[0].body, ASKED);
}

/// While QNTX is down, a gRPC call is told so in gRPC: UNAVAILABLE.
#[tokio::test(flavor = "multi_thread")]
async fn a_grpc_call_while_qntx_is_down_is_unavailable() {
    let qntx = free_addr().await;
    let (front, _run) = laye_front::start(config(qntx, &dir("down")), laye_me::fresh())
        .await
        .unwrap();

    let (status, headers, body, _) = call(front.addr, &signed(&laye_me::fresh())).await;
    assert_eq!(status, 200);
    assert_eq!(headers.get("content-type").unwrap(), "application/grpc");
    assert_eq!(headers.get("grpc-status").unwrap(), "14");
    assert!(
        headers
            .get("grpc-message")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("QNTX did not answer"),
    );
    assert!(body.is_empty());
}
