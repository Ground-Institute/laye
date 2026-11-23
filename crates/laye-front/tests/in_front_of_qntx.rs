#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "LAYE IN FRONT OF QNTX"
// "QNTX CAN GO DOWN"
// "WHILE LAYE IS STILL THERE"
// "AND LAYE OWNS IDENTITY"
// "BUT LAYE DOES NOT REALLY OWN USER, THE QNTX WAY"

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use laye_front::{Config, jwt};
use tokio::net::TcpListener;

const PUBLIC: &str = "https://api.q.example";
const QNTX_DID: &str = "did:key:z6MkqntxNodeStandsHere";

#[derive(Clone, Debug)]
struct Arrived {
    path: String,
    authorization: String,
    body: Vec<u8>,
}

/// A QNTX that keeps what arrives and answers each send with a Task.
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
                let service = hyper::service::service_fn(
                    move |req: Request<hyper::body::Incoming>| {
                        let arrived = arrived.clone();
                        async move {
                            let path = req.uri().path().to_string();
                            let authorization = req
                                .headers()
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or_default()
                                .to_string();
                            let body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
                            arrived.lock().unwrap().push(Arrived {
                                path,
                                authorization,
                                body,
                            });
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            br#"{"task":{"id":"qntx-task-1","status":{"state":"TASK_STATE_SUBMITTED"}}}"#,
                        ))))
                        }
                    },
                );
                if let Err(e) = hyper::server::conn::http1::Builder::new()
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

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn held_at(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("laye-front-{name}-{}", std::process::id()));
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("held.jsonl")
}

fn config(qntx: SocketAddr, held_at: PathBuf) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        qntx: format!("http://{qntx}"),
        qntx_did: QNTX_DID.into(),
        public_origins: vec!["https://laye.example".into(), PUBLIC.into()],
        root_identities: Vec::new(),
        binding_signers: Vec::new(),
        issuer: "https://laye.example".into(),
        nodes: Vec::new(),
        invitations_at: held_at.with_file_name("invitations.jsonl"),
        ceremony_at: "https://node.example".into(),
        names: None,
        passkeys: None,
        web: None,
        apns: None,
        pack_nodes: Vec::new(),
        held_at,
    }
}

/// What a session sends: signed by its own key, for the public origin.
fn session_signs(session: &laye_me::Keypair) -> String {
    let did = laye_peer::did_of(session).unwrap();
    jwt::sign(
        session,
        &jwt::Claims {
            iss: did.clone(),
            sub: did,
            aud: vec![PUBLIC.into()],
            exp: now() + 60,
            jti: jwt::fresh_jti(),
            ..Default::default()
        },
    )
    .unwrap()
}

async fn say(front: SocketAddr, authorization: &str, words: &str) -> (u16, String) {
    let stream = tokio::net::TcpStream::connect(front).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::post("/a2a/Slate/message:send")
        .header("host", "api.q.example")
        .header("authorization", authorization)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(words.to_string())))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// QNTX is handed laye's signature naming the session, never the session's
/// own: laye checked who it is.
#[tokio::test(flavor = "multi_thread")]
async fn laye_checks_who_signed_and_qntx_is_told_by_laye() {
    let arrived = Arc::new(Mutex::new(Vec::new()));
    let qntx = free_addr().await;
    let _qntx = qntx_at(qntx, arrived.clone()).await;
    let laye_key = laye_me::fresh();
    let (front, _run) = laye_front::start(config(qntx, held_at("carry")), laye_key.clone())
        .await
        .unwrap();

    let session = laye_me::fresh();
    let (status, body) = say(
        front.addr,
        &format!("Signed {}", session_signs(&session)),
        "the build on k is red",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("qntx-task-1"), "{body}");

    let got = arrived.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].path, "/a2a/Slate/message:send");
    assert_eq!(got[0].body, b"the build on k is red");
    let carried = got[0].authorization.strip_prefix("Signed ").unwrap();
    let claims = jwt::read(carried).unwrap();
    assert_eq!(claims.iss, laye_peer::did_of(&laye_key).unwrap());
    assert_eq!(claims.sub, laye_peer::did_of(&session).unwrap());
    assert_eq!(claims.aud, vec![QNTX_DID.to_string()]);
}

/// "made me log in"
/// "used passkey"
/// "login again"
///
/// A session QNTX made itself is QNTX's to check: laye hands it on as it came.
#[tokio::test(flavor = "multi_thread")]
async fn qntx_s_own_session_reaches_qntx_as_it_came() {
    let arrived = Arc::new(Mutex::new(Vec::new()));
    let qntx = free_addr().await;
    let _qntx = qntx_at(qntx, arrived.clone()).await;
    let (front, _run) = laye_front::start(config(qntx, held_at("bearer")), laye_me::fresh())
        .await
        .unwrap();

    let (status, body) = say(
        front.addr,
        "Bearer 0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        "the build on k is red",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let got = arrived.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0].authorization,
        "Bearer 0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    );
}

/// A signature that is not the session's, or one presented twice, never
/// reaches QNTX.
#[tokio::test(flavor = "multi_thread")]
async fn what_laye_cannot_verify_never_reaches_qntx() {
    let arrived = Arc::new(Mutex::new(Vec::new()));
    let qntx = free_addr().await;
    let _qntx = qntx_at(qntx, arrived.clone()).await;
    let (front, _run) = laye_front::start(config(qntx, held_at("refuse")), laye_me::fresh())
        .await
        .unwrap();

    // Signed by one key and naming another.
    let session = laye_me::fresh();
    let other = laye_me::fresh();
    let forged = jwt::sign(
        &other,
        &jwt::Claims {
            iss: laye_peer::did_of(&session).unwrap(),
            sub: laye_peer::did_of(&session).unwrap(),
            aud: vec![PUBLIC.into()],
            exp: now() + 60,
            jti: jwt::fresh_jti(),
            ..Default::default()
        },
    )
    .unwrap();
    let (status, _) = say(front.addr, &format!("Signed {forged}"), "x").await;
    assert_eq!(status, 401);

    // For another origin.
    let elsewhere = jwt::sign(
        &session,
        &jwt::Claims {
            iss: laye_peer::did_of(&session).unwrap(),
            sub: laye_peer::did_of(&session).unwrap(),
            aud: vec!["https://somewhere.else".into()],
            exp: now() + 60,
            jti: jwt::fresh_jti(),
            ..Default::default()
        },
    )
    .unwrap();
    let (status, _) = say(front.addr, &format!("Signed {elsewhere}"), "x").await;
    assert_eq!(status, 401);

    // Presented twice.
    let once = format!("Signed {}", session_signs(&session));
    assert_eq!(say(front.addr, &once, "x").await.0, 200);
    assert_eq!(say(front.addr, &once, "x").await.0, 401);

    assert_eq!(arrived.lock().unwrap().len(), 1);
}

/// A send in A2A 1.0, over HTTP+JSON.
const SAID_WHILE_DOWN: &str = r#"{"message":{"messageId":"m-1","role":"ROLE_USER","parts":[{"text":"said while QNTX was down"}]}}"#;

/// What a session says while QNTX is down is kept by laye, and arrives once
/// QNTX is back, though laye itself restarted in between.
#[tokio::test(flavor = "multi_thread")]
async fn qntx_can_go_down_while_laye_is_still_there() {
    let arrived = Arc::new(Mutex::new(Vec::new()));
    let qntx = free_addr().await;
    let held = held_at("down");
    let laye_key = laye_me::fresh();

    let (front, run) = laye_front::start(config(qntx, held.clone()), laye_key.clone())
        .await
        .unwrap();
    let session = laye_me::fresh();
    let (status, body) = say(
        front.addr,
        &format!("Signed {}", session_signs(&session)),
        SAID_WHILE_DOWN,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("TASK_STATE_SUBMITTED"), "{body}");

    // laye goes down and comes back while QNTX is still down.
    run.abort();
    let (_front, _run) = laye_front::start(config(qntx, held.clone()), laye_key.clone())
        .await
        .unwrap();

    // QNTX comes back.
    let _qntx = qntx_at(qntx, arrived.clone()).await;
    until("what was said while QNTX was down never arrived", || {
        !arrived.lock().unwrap().is_empty()
    })
    .await;

    let got = arrived.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].path, "/a2a/Slate/message:send");
    assert_eq!(got[0].body, SAID_WHILE_DOWN.as_bytes());
    let claims = jwt::read(got[0].authorization.strip_prefix("Signed ").unwrap()).unwrap();
    assert_eq!(claims.iss, laye_peer::did_of(&laye_key).unwrap());
    assert_eq!(claims.sub, laye_peer::did_of(&session).unwrap());

    until("what was delivered is still kept", || {
        std::fs::read_to_string(&held)
            .unwrap_or_default()
            .trim()
            .is_empty()
    })
    .await;
}
