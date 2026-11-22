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
// "laye is foundational, while QNTX can remain to be doing experimental things"
//
// No QNTX is started in this file: what laye speaks, it speaks of its own.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use laye_front::a2a_spoken::SPOKEN;
use laye_front::{Config, jwt};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const PUBLIC: &str = "https://api.q.example";

/// Where QNTX would be, and never is.
async fn nowhere() -> SocketAddr {
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
        public_origins: vec!["https://laye.example".into(), PUBLIC.into()],
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

/// laye's card names every version laye speaks, where, at the origin it was
/// asked at; a2a-rs reads it as 1.0, its 0.3 keys name 0.3's interface, and it
/// is signed by laye's key over the card in JCS.
#[tokio::test(flavor = "multi_thread")]
async fn laye_serves_its_own_card_with_qntx_never_up() {
    let key = laye_me::fresh();
    let (front, _run) = laye_front::start(config(nowhere().await, &dir("card")), key.clone())
        .await
        .unwrap();

    let (status, body) = ask(front.addr, "GET", "/.well-known/agent-card.json", None, "").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));

    // 1.0, as a2a-rs reads it.
    let card: a2a::AgentCard = serde_json::from_slice(&body).unwrap();
    let named: Vec<(String, String, String)> = card
        .supported_interfaces
        .iter()
        .map(|i| {
            (
                i.url.clone(),
                i.protocol_binding.clone(),
                i.protocol_version.clone(),
            )
        })
        .collect();
    let spoken: Vec<(String, String, String)> = SPOKEN
        .iter()
        .flat_map(|s| {
            s.bindings.iter().map(|b| {
                (
                    format!("{PUBLIC}{}", s.base),
                    b.to_string(),
                    s.version.to_string(),
                )
            })
        })
        .collect();
    assert_eq!(named, spoken);

    // 0.3, beside it.
    let raw: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(raw["protocolVersion"], "0.3");
    assert_eq!(raw["url"], format!("{PUBLIC}/a2a/0.3"));
    assert_eq!(raw["preferredTransport"], "HTTP+JSON");
    assert_eq!(
        raw["additionalInterfaces"],
        json!([{ "transport": "JSONRPC", "url": format!("{PUBLIC}/a2a/0.3") }])
    );
    assert_eq!(raw["securitySchemes"]["signed"]["type"], "http");

    // Signed by laye's key: the signature verifies over the protected header
    // and the card in JCS, without its signatures.
    let did = laye_peer::did_of(&key).unwrap();
    let signature = &raw["signatures"][0];
    let protected = signature["protected"].as_str().unwrap();
    let header: Value = serde_json::from_slice(&B64URL.decode(protected).unwrap()).unwrap();
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(
        header["kid"],
        format!("{did}#{}", did.strip_prefix("did:key:").unwrap())
    );
    let mut unsigned = raw.clone();
    unsigned.as_object_mut().unwrap().remove("signatures");
    let payload = B64URL.encode(laye_front::a2a_card::jcs(&unsigned).unwrap());
    let signed_over = format!("{protected}.{payload}");
    let bytes = B64URL
        .decode(signature["signature"].as_str().unwrap())
        .unwrap();
    assert!(key.public().verify(signed_over.as_bytes(), &bytes));
}

/// JCS orders members by their names' UTF-16 code units, and writes no space.
#[test]
fn jcs_is_rfc_8785() {
    let value = json!({ "b": [1, "x\n"], "a": { "\u{e9}": true, "Z": null }, "\u{1f600}": 0, "\u{ff61}": 1 });
    let out = String::from_utf8(laye_front::a2a_card::jcs(&value).unwrap()).unwrap();
    assert_eq!(
        out,
        "{\"a\":{\"Z\":null,\"\u{e9}\":true},\"b\":[1,\"x\\n\"],\"\u{1f600}\":0,\"\u{ff61}\":1}"
    );
}

/// With QNTX never up, a send in each version over each binding laye speaks
/// is kept, and answered as that version answers it over that binding: 1.0 as
/// a2a-rs says it, 0.3 as a2a-go's a2av0 says it.
#[tokio::test(flavor = "multi_thread")]
async fn a_send_in_03_or_10_is_answered_with_qntx_never_up() {
    let at = dir("sends");
    let (front, _run) = laye_front::start(config(nowhere().await, &at), laye_me::fresh())
        .await
        .unwrap();

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

    // Every one of them is kept, to be handed over when QNTX is up.
    let kept = std::fs::read_to_string(at.join("held.jsonl")).unwrap();
    assert_eq!(kept.lines().count(), 5);
}

/// What laye does not speak is not kept: QNTX did not answer, and laye says
/// so.
#[tokio::test(flavor = "multi_thread")]
async fn what_laye_does_not_speak_is_not_kept() {
    let at = dir("unspoken");
    let (front, _run) = laye_front::start(config(nowhere().await, &at), laye_me::fresh())
        .await
        .unwrap();

    let session = laye_me::fresh();
    for (path, body) in [
        // 1.0's method, at 0.3's base.
        (
            "/a2a/0.3",
            r#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m","role":"ROLE_USER","parts":[{"text":"x"}]}}}"#,
        ),
        // Nowhere laye speaks A2A.
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
