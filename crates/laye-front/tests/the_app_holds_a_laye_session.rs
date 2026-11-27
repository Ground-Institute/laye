#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "So laye has its own island?"
// "I havent seen it yet."
//
// laye's app proves who it is with its key, as at /laye/login, and is given a
// session; the island presents that session to keep the phone. Each test runs
// a real etcd, the `etcd` on PATH or the one $ETCD names.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use laye_front::passkeys::PasskeysAt;
use laye_front::{Config, NamesAt};
use laye_me::Keypair;
use tokio::net::TcpListener;

const RP: &str = "laye.example";
const AT_RP: &str = "https://laye.example";
const AT_L: &str = "https://l.example";

struct Etcd {
    child: Child,
    at: String,
    data: PathBuf,
}

impl Drop for Etcd {
    fn drop(&mut self) {
        if let Err(e) = self.child.kill() {
            eprintln!("the etcd of this test was not stopped: {e}");
        }
        if let Err(e) = self.child.wait() {
            eprintln!("the etcd of this test did not end: {e}");
        }
        if let Err(e) = std::fs::remove_dir_all(&self.data) {
            eprintln!("{} was not removed: {e}", self.data.display());
        }
    }
}

async fn free_addr() -> SocketAddr {
    let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
    held.local_addr().unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("laye-passkeys-{name}-{}", std::process::id()));
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn etcd(name: &str) -> Etcd {
    let binary = std::env::var("ETCD").unwrap_or_else(|_| "etcd".into());
    let client = free_addr().await;
    let peer = free_addr().await;
    let data = scratch(&format!("{name}-etcd"));
    let child = Command::new(&binary)
        .args(["--name", "t", "--data-dir"])
        .arg(&data)
        .args([
            "--listen-client-urls",
            &format!("http://{client}"),
            "--advertise-client-urls",
            &format!("http://{client}"),
            "--listen-peer-urls",
            &format!("http://{peer}"),
            "--initial-advertise-peer-urls",
            &format!("http://{peer}"),
            "--initial-cluster",
            &format!("t=http://{peer}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("{binary} did not start; these tests run a real etcd: {e}"));
    let etcd = Etcd {
        child,
        at: format!("http://{client}"),
        data,
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(answer) = ask(
            client,
            "127.0.0.1",
            "POST",
            "/v3/kv/range",
            "",
            r#"{"key":"AA=="}"#,
        )
        .await
            && answer.status == 200
        {
            return etcd;
        }
        assert!(Instant::now() < deadline, "etcd at {client} never answered");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

struct Answer {
    status: u16,
    body: serde_json::Value,
    text: String,
    cookie: Option<String>,
}

async fn ask(
    to: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    cookie: &str,
    body: &str,
) -> Result<Answer, String> {
    asked(to, host, method, path, cookie, "", body).await
}

async fn asked(
    to: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    cookie: &str,
    authorization: &str,
    body: &str,
) -> Result<Answer, String> {
    let stream = tokio::net::TcpStream::connect(to)
        .await
        .map_err(|e| e.to_string())?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .header("content-type", "application/json");
    if !cookie.is_empty() {
        req = req.header("cookie", cookie);
    }
    if !authorization.is_empty() {
        req = req.header("authorization", authorization);
    }
    let resp = sender
        .send_request(req.body(Full::new(Bytes::from(body.to_string()))).unwrap())
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::to_string);
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Ok(Answer {
        status,
        body: serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
        text,
        cookie,
    })
}

/// A laye on this etcd, with nothing behind it: its QNTX never answers.
async fn laye(name: &str, etcd: &str, roots: Vec<String>, signers: Vec<String>) -> SocketAddr {
    let dir = scratch(name);
    let (front, _run) = laye_front::start(
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            qntx: format!("http://{}", free_addr().await),
            qntx_did: "did:key:z6MkqntxNodeStandsHere".into(),
            public_origins: vec![AT_RP.into(), "https://api.q.example".into()],
            held_at: dir.join("held.jsonl"),
            root_identities: roots,
            binding_signers: signers,
            issuer: AT_RP.into(),
            nodes: Vec::new(),
            invitations_at: dir.join("invitations.jsonl"),
            ceremony_at: "https://node.example".into(),
            names: Some(NamesAt {
                etcd: etcd.into(),
                admitters: Vec::new(),
                etcd_user: None,
                etcd_password_file: None,
            }),
            passkeys: Some(PasskeysAt {
                rp_id: RP.into(),
                origins: vec![AT_RP.into(), AT_L.into()],
            }),
            web: None,
            apns: None,
            pack_nodes: Vec::new(),
            governed: None,
        },
        laye_me::fresh(),
    )
    .await
    .unwrap();
    front.addr
}

fn did(key: &Keypair) -> String {
    laye_peer::did_of(key).unwrap()
}

/// What laye's app asks with: laye's challenge, signed by its key.
async fn proof(at: SocketAddr, key: &Keypair) -> String {
    let challenge = ask(at, RP, "GET", "/laye/challenge", "", "").await.unwrap();
    assert_eq!(challenge.status, 200, "{}", challenge.text);
    let challenge = challenge.body["challenge"].as_str().unwrap().to_string();
    serde_json::json!({
        "did": did(key),
        "signature": B64URL.encode(key.sign(challenge.as_bytes()).unwrap()),
        "challenge": challenge,
        "bindings": [],
    })
    .to_string()
}

#[tokio::test]
async fn the_app_is_given_a_session_and_its_island_keeps_the_phone() {
    let store = etcd("app-session").await;
    let key = laye_me::fresh();
    let at = laye("app-session", &store.at, vec![did(&key)], Vec::new()).await;

    let given = ask(at, RP, "POST", "/laye/session", "", &proof(at, &key).await)
        .await
        .unwrap();
    assert_eq!(given.status, 200, "{}", given.text);
    assert_eq!(given.body["person"], did(&key));
    assert_eq!(given.body["level"], "ROOT");
    let session = given.body["session"].as_str().unwrap().to_string();
    // The same session, as laye's own page would hold it.
    assert_eq!(given.cookie, Some(format!("laye_person={session}")));

    let phone = serde_json::json!({ "token": "ab".repeat(32) }).to_string();
    let none = ask(at, RP, "POST", "/api/phones", "", &phone)
        .await
        .unwrap();
    assert_eq!(
        none.status, 401,
        "a phone was kept with no session: {}",
        none.text
    );
    let kept = asked(
        at,
        RP,
        "POST",
        "/api/phones",
        "",
        &format!("Bearer {session}"),
        &phone,
    )
    .await
    .unwrap();
    assert_eq!(kept.status, 200, "{}", kept.text);
}

#[tokio::test]
async fn a_key_laye_does_not_know_is_given_no_session() {
    let store = etcd("app-stranger").await;
    let root = laye_me::fresh();
    let stranger = laye_me::fresh();
    let at = laye("app-stranger", &store.at, vec![did(&root)], Vec::new()).await;
    let given = ask(
        at,
        RP,
        "POST",
        "/laye/session",
        "",
        &proof(at, &stranger).await,
    )
    .await
    .unwrap();
    assert_eq!(given.status, 403, "{}", given.text);
}

#[tokio::test]
async fn a_spent_challenge_is_given_no_session() {
    let store = etcd("app-spent").await;
    let key = laye_me::fresh();
    let at = laye("app-spent", &store.at, vec![did(&key)], Vec::new()).await;
    let once = proof(at, &key).await;
    assert_eq!(
        ask(at, RP, "POST", "/laye/session", "", &once)
            .await
            .unwrap()
            .status,
        200
    );
    assert_eq!(
        ask(at, RP, "POST", "/laye/session", "", &once)
            .await
            .unwrap()
            .status,
        401
    );
}
