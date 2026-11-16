#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "do we support 0.3 yes or not, if not, make it support it, period"
// "laye would help us still be A2A capable, even when QNTX is down"
// "For the 0.3 rows, laye either answers 0.3 itself,"
// "sure, this is fine"

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use laye_front::{Config, jwt};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const PUBLIC: &str = "https://api.q.example";

/// The card QNTX serves: each A2A version where its path says, as QNTX's
/// a2aSpoken table mounts them (server/a2a_versions.go).
const CARD: &str = r#"{"name":"q","supportedInterfaces":[
{"url":"https://api.q.example/a2a","protocolBinding":"HTTP+JSON","protocolVersion":"1.0"},
{"url":"https://api.q.example/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"},
{"url":"https://api.q.example/a2a/0.3","protocolBinding":"HTTP+JSON","protocolVersion":"0.3"},
{"url":"https://api.q.example/a2a/0.3","protocolBinding":"JSONRPC","protocolVersion":"0.3"}]}"#;

/// A QNTX that serves its card, and closes each connection after answering:
/// once it stops, nothing of it is left to answer.
async fn qntx_at(addr: SocketAddr) -> tokio::task::JoinHandle<()> {
    let listener = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let service =
                    hyper::service::service_fn(|_: Request<hyper::body::Incoming>| async {
                        let mut resp =
                            Response::new(Full::new(Bytes::from_static(CARD.as_bytes())));
                        resp.headers_mut().insert(
                            "connection",
                            hyper::header::HeaderValue::from_static("close"),
                        );
                        Ok::<_, Infallible>(resp)
                    });
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .keep_alive(false)
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
    let dir = std::env::temp_dir().join(format!("laye-a2a-{name}-{}", std::process::id()));
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
        qntx_did: "did:key:z6MkqntxNodeStandsHere".into(),
        public_origins: vec![PUBLIC.into()],
        held_at: dir.join("held.jsonl"),
        card_at: dir.join("card.json"),
        root_identities: Vec::new(),
        binding_signers: Vec::new(),
        issuer: "https://laye.example".into(),
        nodes: Vec::new(),
        invitations_at: dir.join("invitations.jsonl"),
        ceremony_at: "https://node.example".into(),
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

async fn ask(
    front: SocketAddr,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    body: &str,
) -> (u16, Vec<u8>) {
    let stream = tokio::net::TcpStream::connect(front).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "api.q.example")
        .header("content-type", "application/json");
    if let Some(authorization) = authorization {
        req = req.header("authorization", authorization);
    }
    let resp = sender
        .send_request(req.body(Full::new(Bytes::from(body.to_string()))).unwrap())
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (
        status,
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
}

/// The card QNTX served is the card laye serves once QNTX is down, byte for
/// byte: it is signed over those bytes.
#[tokio::test(flavor = "multi_thread")]
async fn the_card_qntx_served_is_served_while_it_is_down() {
    let qntx = free_addr().await;
    let at = dir("card");
    let running = qntx_at(qntx).await;
    let (front, _run) = laye_front::start(config(qntx, &at), laye_me::fresh())
        .await
        .unwrap();

    let (status, up) = ask(front.addr, "GET", "/.well-known/agent-card.json", None, "").await;
    assert_eq!(status, 200);
    assert_eq!(up, CARD.as_bytes());

    running.abort();
    let (status, down) = ask(front.addr, "GET", "/.well-known/agent-card.json", None, "").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&down));
    assert_eq!(down, up);
}

/// While QNTX is down, a send in each version over each binding its card
/// names is kept, and answered as that version answers it over that binding:
/// 1.0 as a2a-rs says it, 0.3 as a2a-go's a2av0 says it.
#[tokio::test(flavor = "multi_thread")]
async fn a_send_in_03_or_10_is_answered_while_qntx_is_down() {
    let qntx = free_addr().await;
    let at = dir("sends");
    let running = qntx_at(qntx).await;
    let (front, _run) = laye_front::start(config(qntx, &at), laye_me::fresh())
        .await
        .unwrap();
    assert_eq!(
        ask(front.addr, "GET", "/.well-known/agent-card.json", None, "")
            .await
            .0,
        200
    );
    running.abort();

    let session = laye_me::fresh();
    let message_10 = json!({"messageId":"m-10","role":"ROLE_USER","parts":[{"text":"hello"}],"contextId":"c-10"});
    let message_03 = json!({"kind":"message","messageId":"m-03","role":"user","parts":[{"kind":"text","text":"hello"}],"contextId":"c-03"});

    // 1.0 over HTTP+JSON, at no tenant and at one.
    for path in ["/a2a/message:send", "/a2a/garden/message:send"] {
        let (status, body) = ask(
            front.addr,
            "POST",
            path,
            Some(&signed(&session)),
            &json!({ "message": message_10 }).to_string(),
        )
        .await;
        assert_eq!(status, 200, "{path}: {}", String::from_utf8_lossy(&body));
        let task = serde_json::from_slice::<Value>(&body).unwrap()["task"].clone();
        assert_eq!(task["contextId"], "c-10", "{path}");
        assert_eq!(task["status"]["state"], "TASK_STATE_SUBMITTED", "{path}");
        assert!(
            task["id"].as_str().unwrap().starts_with("laye-held-"),
            "{path}"
        );
    }

    // 1.0 over JSON-RPC.
    let (status, body) = ask(
        front.addr,
        "POST",
        "/a2a",
        Some(&signed(&session)),
        &json!({"jsonrpc":"2.0","id":7,"method":"SendMessage","params":{"message":message_10}})
            .to_string(),
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let answer: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(answer["jsonrpc"], "2.0");
    assert_eq!(answer["id"], 7);
    assert_eq!(answer["result"]["task"]["contextId"], "c-10");
    assert_eq!(
        answer["result"]["task"]["status"]["state"],
        "TASK_STATE_SUBMITTED"
    );

    // 0.3 over HTTP+JSON: ProtoJSON, as a2av0's REST handler writes it.
    let (status, body) = ask(
        front.addr,
        "POST",
        "/a2a/0.3/v1/message:send",
        Some(&signed(&session)),
        &json!({"message":{"messageId":"m-03","role":"ROLE_USER","content":[{"text":"hello"}],"contextId":"c-03"}})
            .to_string(),
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let task = serde_json::from_slice::<Value>(&body).unwrap()["task"].clone();
    assert_eq!(task["contextId"], "c-03");
    assert_eq!(task["status"]["state"], "TASK_STATE_SUBMITTED");

    // 0.3 over JSON-RPC: the Task itself, of kind task, as a2av0's JSON-RPC
    // handler writes it.
    let (status, body) = ask(
        front.addr,
        "POST",
        "/a2a/0.3",
        Some(&signed(&session)),
        &json!({"jsonrpc":"2.0","id":"x-03","method":"message/send","params":{"message":message_03}})
            .to_string(),
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let answer: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(answer["id"], "x-03");
    assert_eq!(answer["result"]["kind"], "task");
    assert_eq!(answer["result"]["contextId"], "c-03");
    assert_eq!(answer["result"]["status"]["state"], "submitted");

    // Every one of them is kept, to be handed over when QNTX is back.
    let kept = std::fs::read_to_string(at.join("held.jsonl")).unwrap();
    assert_eq!(kept.lines().count(), 5);
}

/// What no interface of the card takes is not kept: QNTX did not answer, and
/// laye says so.
#[tokio::test(flavor = "multi_thread")]
async fn what_the_card_does_not_name_is_not_kept() {
    let qntx = free_addr().await;
    let at = dir("unnamed");
    let running = qntx_at(qntx).await;
    let (front, _run) = laye_front::start(config(qntx, &at), laye_me::fresh())
        .await
        .unwrap();
    assert_eq!(
        ask(front.addr, "GET", "/.well-known/agent-card.json", None, "")
            .await
            .0,
        200
    );
    running.abort();

    let session = laye_me::fresh();
    for (path, body) in [
        // 1.0's method, at 0.3's interface.
        (
            "/a2a/0.3",
            r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m","role":"ROLE_USER","parts":[{"text":"x"}]}}}"#,
        ),
        // Nowhere the card names.
        (
            "/elsewhere/message:send",
            r#"{"message":{"messageId":"m","role":"ROLE_USER","parts":[{"text":"x"}]}}"#,
        ),
    ] {
        let (status, _) = ask(front.addr, "POST", path, Some(&signed(&session)), body).await;
        assert_eq!(status, 503, "{path}");
    }
    assert!(!at.join("held.jsonl").exists());
}
