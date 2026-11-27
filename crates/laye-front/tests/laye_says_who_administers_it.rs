#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "its the story of someone verifying they can trust laye the network they are about to join, with their agent"
// "can't we have it work in a way that we dont need to build the same parser twice?"
// "laye doesnt parse pbt yet."
//
// laye answers who administers it from what ground's pbt says of it, as the
// data `ground laye json` writes (Ground-Code source/administers.d asData).
// No QNTX is started: laye answers this of its own.

use std::net::SocketAddr;
use std::path::PathBuf;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use laye_front::{Config, Governed};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// What `ground laye json` writes for laye.ground.institute.
const GROUND_SAYS: &str =
    r#"{"url":"https://laye.ground.institute","org":"Ground-Institute","administrator":"teranos"}"#;

async fn nowhere() -> SocketAddr {
    let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
    held.local_addr().unwrap()
}

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("laye-administers-{name}-{}", std::process::id()));
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn config(qntx: SocketAddr, dir: &std::path::Path, governed: Option<Governed>) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        qntx: format!("http://{qntx}"),
        qntx_did: "did:key:z6MkqntxNodeStandsHere".into(),
        public_origins: vec!["https://laye.ground.institute".into()],
        held_at: dir.join("held.jsonl"),
        root_identities: Vec::new(),
        binding_signers: Vec::new(),
        issuer: "https://laye.ground.institute".into(),
        nodes: Vec::new(),
        invitations_at: dir.join("invitations.jsonl"),
        ceremony_at: "https://node.example".into(),
        names: None,
        passkeys: None,
        web: None,
        apns: None,
        pack_nodes: Vec::new(),
        governed,
    }
}

async fn get(front: SocketAddr, path: &str) -> (u16, Value, String) {
    let stream = tokio::net::TcpStream::connect(front).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", "laye.ground.institute")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let text =
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    )
}

/// Whether the account a name is administers this laye, as ground says;
/// and nothing else about anyone. As C answers it today.
#[tokio::test(flavor = "multi_thread")]
async fn laye_says_who_administers_it_as_ground_says() {
    let governed: Governed = serde_json::from_str(GROUND_SAYS).unwrap();
    let dir = dir("says");
    let (front, _run) = laye_front::start(
        config(nowhere().await, &dir, Some(governed)),
        laye_me::fresh(),
    )
    .await
    .unwrap();

    let (status, body, text) = get(front.addr, "/laye/administrator/teranos").await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(
        body,
        json!({ "administrator": "teranos", "administers": true })
    );

    let (status, body, text) = get(front.addr, "/laye/administrator/someone").await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(
        body,
        json!({ "administrator": "someone", "administers": false })
    );
}

/// A laye ground said nothing of says so, rather than that nobody administers it.
#[tokio::test(flavor = "multi_thread")]
async fn a_laye_ground_said_nothing_of_says_so() {
    let dir = dir("nothing");
    let (front, _run) = laye_front::start(config(nowhere().await, &dir, None), laye_me::fresh())
        .await
        .unwrap();

    let (status, _, text) = get(front.addr, "/laye/administrator/teranos").await;
    assert_eq!(status, 503, "{text}");
    assert!(
        text.contains("this laye was given nothing ground says of it"),
        "{text}"
    );
}
