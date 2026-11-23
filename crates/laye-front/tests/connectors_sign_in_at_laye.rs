#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "BUT I WANT LAYE TO OWN IT, LAYE IS SUPPOSED TO FALL DOWN LESS EASILY THAN QNTX"
//
// A connector, claude.ai or ChatGPT, sends a person to laye's screen, is sent
// back a code, and is handed a token and a refresh token laye keeps in etcd.
// The node asks laye who the token is. Each test runs a real etcd, the `etcd`
// on PATH or the one $ETCD names.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use laye_front::passkeys::PasskeysAt;
use laye_front::{Config, NamesAt, Node};
use laye_me::Keypair;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

const RP: &str = "laye.example";
const AT_RP: &str = "https://laye.example";
const NODE_AT: &str = "https://api.q.example";
const CLIENT: &str = "did:key:z6MkConnectorClaudeStandsHere";
const BACK: &str = "https://claude.example/api/mcp/auth_callback";
const SECRET: &str = "qntx_the-connector-s-secret";
const VERIFIER: &str = "a-verifier-only-the-connector-holds-0123456789";

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
    let dir = std::env::temp_dir().join(format!("laye-connectors-{name}-{}", std::process::id()));
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
}

async fn ask(
    to: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
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
        .header("host", host);
    if !authorization.is_empty() {
        req = req.header("authorization", authorization);
    }
    let resp = sender
        .send_request(req.body(Full::new(Bytes::from(body.to_string()))).unwrap())
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
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
    })
}

fn did(key: &Keypair) -> String {
    laye_peer::did_of(key).unwrap()
}

fn encoded(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encoded(k), encoded(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn hex_sha256(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn basic() -> String {
    format!(
        "Basic {}",
        B64.encode(format!("{}:{}", encoded(CLIENT), encoded(SECRET)))
    )
}

struct At {
    laye: SocketAddr,
    node: Keypair,
}

/// A laye on this etcd that issues for one connector, ROOT's, whose tokens
/// are for the node.
async fn laye(name: &str, store: &Etcd, roots: Vec<String>) -> At {
    let node = laye_me::fresh();
    let dir = scratch(name);
    let (front, _run) = laye_front::start(
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            qntx: format!("http://{}", free_addr().await),
            qntx_did: did(&node),
            public_origins: vec![AT_RP.into(), NODE_AT.into()],
            held_at: dir.join("held.jsonl"),
            root_identities: roots,
            binding_signers: Vec::new(),
            issuer: AT_RP.into(),
            nodes: vec![Node {
                did: did(&node),
                back: format!("{NODE_AT}/auth/elsewhere/back"),
            }],
            invitations_at: dir.join("invitations.jsonl"),
            ceremony_at: NODE_AT.into(),
            names: Some(NamesAt {
                etcd: store.at.clone(),
                admitters: Vec::new(),
                etcd_user: None,
                etcd_password_file: None,
            }),
            passkeys: Some(PasskeysAt {
                rp_id: RP.into(),
                origins: vec![AT_RP.into()],
            }),
            web: None,
            apns: None,
            pack_nodes: Vec::new(),
        },
        laye_me::fresh(),
    )
    .await
    .unwrap();
    let client = serde_json::json!({
        "did": CLIENT,
        "label": "CLAUDEAI",
        "back": BACK,
        "secret": hex_sha256(SECRET),
        "root": true,
        "namespaces": [],
        "node": did(&node),
        "resource": NODE_AT,
    });
    let etcd_at: SocketAddr = store.at.trim_start_matches("http://").parse().unwrap();
    let put = serde_json::json!({
        "key": B64.encode(format!("/oauth/clients/{CLIENT}")),
        "value": B64.encode(client.to_string()),
    });
    let kept = ask(
        etcd_at,
        "127.0.0.1",
        "POST",
        "/v3/kv/put",
        "",
        &put.to_string(),
    )
    .await
    .unwrap();
    assert_eq!(kept.status, 200, "{}", kept.text);
    At {
        laye: front.addr,
        node,
    }
}

fn journey() -> String {
    let challenge = B64URL.encode(Sha256::digest(VERIFIER.as_bytes()));
    form(&[
        ("response_type", "code"),
        ("client_id", CLIENT),
        ("redirect_uri", BACK),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("state", "the-connector-s-state"),
        ("resource", &format!("{NODE_AT}/mcp")),
    ])
}

/// A person signs in on laye's screen for the connector: the code it is sent
/// back with, or laye's refusal.
async fn signed_in(at: &At, person: &Keypair) -> Result<String, Answer> {
    let challenge = ask(at.laye, RP, "GET", "/laye/challenge", "", "")
        .await
        .unwrap();
    let challenge = challenge.body["challenge"].as_str().unwrap().to_string();
    let login = serde_json::json!({
        "did": did(person),
        "signature": B64URL.encode(person.sign(challenge.as_bytes()).unwrap()),
        "challenge": challenge,
        "bindings": [],
        "authorize": journey(),
    });
    let answer = ask(at.laye, RP, "POST", "/laye/login", "", &login.to_string())
        .await
        .unwrap();
    if answer.status != 200 {
        return Err(answer);
    }
    let redirect = answer.body["redirect"].as_str().unwrap().to_string();
    assert!(redirect.starts_with(&format!("{BACK}?code=")), "{redirect}");
    assert!(
        redirect.ends_with("&state=the-connector-s-state"),
        "{redirect}"
    );
    let code = redirect
        .split_once("code=")
        .unwrap()
        .1
        .split('&')
        .next()
        .unwrap()
        .to_string();
    Ok(code)
}

async fn token(at: &At, asked: &[(&str, &str)]) -> Answer {
    ask(at.laye, RP, "POST", "/auth/token", &basic(), &form(asked))
        .await
        .unwrap()
}

async fn by_code(at: &At, code: &str) -> Answer {
    token(
        at,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", BACK),
            ("code_verifier", VERIFIER),
            ("resource", &format!("{NODE_AT}/mcp")),
        ],
    )
    .await
}

async fn by_refresh(at: &At, refresh: &str) -> Answer {
    token(
        at,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("resource", &format!("{NODE_AT}/mcp")),
        ],
    )
    .await
}

/// The node asks laye who a token is, signing as itself.
async fn introspected(at: &At, token: &str) -> Answer {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let assertion = laye_front::jwt::sign(
        &at.node,
        &laye_front::jwt::Claims {
            iss: did(&at.node),
            sub: did(&at.node),
            aud: vec![format!("{AT_RP}/auth/token")],
            exp: now + 60,
            iat: now,
            jti: laye_front::jwt::fresh_jti(),
            label: String::new(),
        },
    )
    .unwrap();
    let asked = form(&[
        ("token", token),
        ("client_id", &did(&at.node)),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", &assertion),
    ]);
    ask(at.laye, RP, "POST", "/auth/introspect", "", &asked)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_connector_signs_a_person_in_at_laye_and_the_node_asks_laye_who_its_token_is() {
    let store = etcd("signs-in").await;
    let root = laye_me::fresh();
    let at = laye("signs-in", &store, vec![did(&root)]).await;

    let page = ask(
        at.laye,
        RP,
        "GET",
        &format!("/auth/authorize?{}", journey()),
        "",
        "",
    )
    .await
    .unwrap();
    assert_eq!(page.status, 200, "{}", page.text);

    let code = signed_in(&at, &root)
        .await
        .unwrap_or_else(|a| panic!("{}", a.text));
    let given = by_code(&at, &code).await;
    assert_eq!(given.status, 200, "{}", given.text);
    let access = given.body["access_token"].as_str().unwrap().to_string();
    assert!(access.starts_with("qntx_"), "{access}");
    assert!(
        given.body["refresh_token"].as_str().is_some(),
        "{}",
        given.text
    );

    let who = introspected(&at, &access).await;
    assert_eq!(who.status, 200, "{}", who.text);
    assert_eq!(who.body["active"], true, "{}", who.text);
    assert_eq!(who.body["sub"], did(&root));
    assert_eq!(who.body["level"], "ROOT");
    assert_eq!(who.body["client_id"], CLIENT);
    assert_eq!(who.body["label"], "CLAUDEAI");
    assert_eq!(who.body["iss"], AT_RP);
    assert!(
        who.body["did"]
            .as_str()
            .unwrap()
            .starts_with("did:key:z6Mk"),
        "{}",
        who.text
    );

    // A code is spent once.
    assert_eq!(by_code(&at, &code).await.status, 400);
}

#[tokio::test]
async fn a_refresh_writes_the_next_and_spends_the_one_presented_together() {
    let store = etcd("refresh").await;
    let root = laye_me::fresh();
    let at = laye("refresh", &store, vec![did(&root)]).await;
    let code = signed_in(&at, &root)
        .await
        .unwrap_or_else(|a| panic!("{}", a.text));
    let first = by_code(&at, &code).await;
    let r1 = first.body["refresh_token"].as_str().unwrap().to_string();

    let second = by_refresh(&at, &r1).await;
    assert_eq!(second.status, 200, "{}", second.text);
    let r2 = second.body["refresh_token"].as_str().unwrap().to_string();
    let a2 = second.body["access_token"].as_str().unwrap().to_string();
    assert_ne!(r1, r2);
    assert_eq!(introspected(&at, &a2).await.body["active"], true);

    let third = by_refresh(&at, &r2).await;
    assert_eq!(third.status, 200, "{}", third.text);
    let r3 = third.body["refresh_token"].as_str().unwrap().to_string();
    let a3 = third.body["access_token"].as_str().unwrap().to_string();

    // "A refresh token presented twice is still treated as stolen, as qq does now."
    let stolen = by_refresh(&at, &r1).await;
    assert_eq!(stolen.status, 400, "{}", stolen.text);
    assert_eq!(stolen.body["error"], "invalid_grant");
    assert_eq!(introspected(&at, &a3).await.body["active"], false);
    let after = by_refresh(&at, &r3).await;
    assert_eq!(after.status, 400, "{}", after.text);
    assert_eq!(after.body["error"], "invalid_grant");
}

#[tokio::test]
async fn a_connector_presenting_another_secret_is_refused() {
    let store = etcd("secret").await;
    let root = laye_me::fresh();
    let at = laye("secret", &store, vec![did(&root)]).await;
    let code = signed_in(&at, &root)
        .await
        .unwrap_or_else(|a| panic!("{}", a.text));
    let wrong = format!(
        "Basic {}",
        B64.encode(format!("{}:qntx_another", encoded(CLIENT)))
    );
    let asked = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", BACK),
        ("code_verifier", VERIFIER),
    ]);
    let refused = ask(at.laye, RP, "POST", "/auth/token", &wrong, &asked)
        .await
        .unwrap();
    assert_eq!(refused.status, 401, "{}", refused.text);
    assert_eq!(refused.body["error"], "invalid_client");
}

#[tokio::test]
async fn roots_client_is_sent_no_code_for_somebody_who_is_not_root() {
    let store = etcd("not-root").await;
    let root = laye_me::fresh();
    let stranger = laye_me::fresh();
    let at = laye("not-root", &store, vec![did(&root)]).await;
    let refused = signed_in(&at, &stranger).await.err().unwrap();
    assert_eq!(refused.status, 403, "{}", refused.text);
}

#[tokio::test]
async fn a_refresh_token_laye_did_not_issue_goes_on_to_the_node() {
    let store = etcd("not-layes").await;
    let root = laye_me::fresh();
    let at = laye("not-layes", &store, vec![did(&root)]).await;
    // The node behind this laye never answers.
    let handed = by_refresh(&at, "ory_rt_one-the-node-issued").await;
    assert_eq!(handed.status, 503, "{}", handed.text);
    assert!(
        handed.text.contains("QNTX did not answer"),
        "{}",
        handed.text
    );
}
