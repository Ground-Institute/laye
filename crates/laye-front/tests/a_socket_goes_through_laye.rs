#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "LAYE IN FRONT OF QNTX"

// QNTX's page keeps a WebSocket open to the node; in front of QNTX, laye
// carries it, and says whose it is as for any request.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use laye_front::{Config, jwt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PUBLIC: &str = "https://api.q.example";

/// A QNTX that upgrades every request and echoes what comes over it, keeping
/// the Authorization the upgrade came with.
async fn echoing_qntx(seen: Arc<Mutex<Vec<String>>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let service =
                    hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                        let seen = seen.clone();
                        async move {
                            seen.lock().unwrap().push(
                                req.headers()
                                    .get("authorization")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or_default()
                                    .to_string(),
                            );
                            let upgrade = hyper::upgrade::on(&mut req);
                            tokio::spawn(async move {
                                let mut io = TokioIo::new(upgrade.await.unwrap());
                                let mut buf = [0u8; 64];
                                loop {
                                    let n = io.read(&mut buf).await.unwrap();
                                    if n == 0 {
                                        return;
                                    }
                                    io.write_all(&buf[..n]).await.unwrap();
                                }
                            });
                            let mut resp = Response::new(Full::new(Bytes::new()));
                            *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                            resp.headers_mut()
                                .insert("connection", "upgrade".parse().unwrap());
                            resp.headers_mut()
                                .insert("upgrade", "websocket".parse().unwrap());
                            Ok::<_, Infallible>(resp)
                        }
                    });
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await
                    .unwrap();
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn a_websocket_goes_through_laye_and_qntx_is_told_whose_it_is() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let qntx = echoing_qntx(seen.clone()).await;
    let dir = std::env::temp_dir().join(format!("laye-socket-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let laye_key = laye_me::fresh();
    let (front, _run) = laye_front::start(
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            qntx: format!("http://{qntx}"),
            qntx_did: "did:key:z6MkqntxNodeStandsHere".into(),
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
        },
        laye_key.clone(),
    )
    .await
    .unwrap();

    let session = laye_me::fresh();
    let session_did = laye_peer::did_of(&session).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signed = jwt::sign(
        &session,
        &jwt::Claims {
            iss: session_did.clone(),
            sub: session_did.clone(),
            aud: vec![PUBLIC.into()],
            exp: now + 60,
            jti: jwt::fresh_jti(),
            ..Default::default()
        },
    )
    .unwrap();

    let stream = tokio::net::TcpStream::connect(front.addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn.with_upgrades());
    let req = Request::get("/ws")
        .header("host", "api.q.example")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("authorization", format!("Signed {signed}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    let mut io = TokioIo::new(hyper::upgrade::on(resp).await.unwrap());
    io.write_all(b"through laye").await.unwrap();
    let mut back = [0u8; 12];
    io.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"through laye");

    let authorization = seen.lock().unwrap()[0].clone();
    let claims = jwt::read(authorization.strip_prefix("Signed ").unwrap()).unwrap();
    assert_eq!(claims.iss, laye_peer::did_of(&laye_key).unwrap());
    assert_eq!(claims.sub, session_did);
}
