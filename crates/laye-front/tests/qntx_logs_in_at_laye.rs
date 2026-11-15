#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "so laye owns login as well"
// "the lgin screen, you would be seeing laye"
// "and QNTX and a QNTX Node Namespaces, likewise delegate this out to laye"

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use laye_front::{Config, Node, jwt};

const ISSUER: &str = "https://laye.example";
const BACK: &str = "https://node.example/auth/elsewhere/back";
const ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn did(key: &laye_me::Keypair) -> String {
    laye_peer::did_of(key).unwrap()
}

fn held_at(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("laye-issuer-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("held.jsonl")
}

async fn laye(name: &str, root: &laye_me::Keypair, node: &laye_me::Keypair) -> SocketAddr {
    let (front, run) = laye_front::start(
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            qntx: "http://127.0.0.1:9".into(),
            qntx_did: did(node),
            public_origins: vec![ISSUER.into()],
            held_at: held_at(name),
            invitations_at: held_at(name).with_file_name("invitations.jsonl"),
            ceremony_at: "https://node.example".into(),
            root_identities: vec![did(root)],
            binding_signers: Vec::new(),
            issuer: ISSUER.into(),
            nodes: vec![Node {
                did: did(node),
                back: BACK.into(),
            }],
        },
        laye_me::fresh(),
    )
    .await
    .unwrap();
    std::mem::forget(run);
    front.addr
}

async fn ask(at: SocketAddr, method: &str, path: &str, body: String) -> (u16, String) {
    let stream = tokio::net::TcpStream::connect(at).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let content_type = if body.starts_with('{') {
        "application/json"
    } else {
        "application/x-www-form-urlencoded"
    };
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "laye.example")
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// What QNTX signs to ask laye anything: its own key, for laye's token address.
fn node_asserts(node: &laye_me::Keypair) -> String {
    jwt::sign(
        node,
        &jwt::Claims {
            iss: did(node),
            sub: did(node),
            aud: vec![format!("{ISSUER}/auth/token")],
            exp: now() + 60,
            iat: now(),
            jti: jwt::fresh_jti(),
            ..Default::default()
        },
    )
    .unwrap()
}

fn query_of(location: &str, name: &str) -> String {
    let (_, query) = location.split_once('?').unwrap();
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
        .unwrap()
        .to_string()
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).to_vec()
}

/// Somebody logs in at laye, the way QNTX sends them: laye's screen, laye's
/// challenge, and where laye sends them back to.
async fn logs_in(
    at: SocketAddr,
    who: &laye_me::Keypair,
    node: &laye_me::Keypair,
    verifier: &str,
) -> (u16, String) {
    let challenge = B64URL.encode(sha256(verifier.as_bytes()));
    let authorize = form(&[
        ("client_id", &did(node)),
        ("redirect_uri", BACK),
        ("response_type", "code"),
        ("state", "the-state"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]);
    let (status, page) = ask(
        at,
        "GET",
        &format!("/auth/authorize?{authorize}"),
        String::new(),
    )
    .await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("laye"), "the login screen is laye's: {page}");
    assert!(page.contains("#050608"), "laye's screen has laye's look");
    assert!(
        page.contains(r#"const CEREMONY = "https://node.example";"#),
        "{page}"
    );
    assert!(
        !page.contains("{{"),
        "everything on the screen is filled in"
    );

    let (_, issued) = ask(at, "GET", "/laye/challenge", String::new()).await;
    let issued: serde_json::Value = serde_json::from_str(&issued).unwrap();
    let said = issued["challenge"].as_str().unwrap().to_string();
    let login = serde_json::json!({
        "did": did(who),
        "signature": B64URL.encode(who.sign(said.as_bytes()).unwrap()),
        "challenge": said,
        "bindings": [],
        "authorize": authorize,
    });
    ask(at, "POST", "/laye/login", login.to_string()).await
}

fn token_form(code: &str, verifier: &str, node: &laye_me::Keypair) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", BACK),
        ("code_verifier", verifier),
        ("client_id", &did(node)),
        ("client_assertion_type", ASSERTION),
        ("client_assertion", &node_asserts(node)),
    ])
}

#[tokio::test(flavor = "multi_thread")]
async fn qntx_sends_a_root_to_laye_and_laye_says_who_they_are() {
    let root = laye_me::fresh();
    let node = laye_me::fresh();
    let at = laye("whole", &root, &node).await;

    let (_, meta) = ask(
        at,
        "GET",
        "/.well-known/oauth-authorization-server",
        String::new(),
    )
    .await;
    let meta: serde_json::Value = serde_json::from_str(&meta).unwrap();
    assert_eq!(meta["issuer"], ISSUER);
    assert!(meta["did"].as_str().unwrap().starts_with("did:key:"));

    let verifier = "a-verifier-only-qntx-holds-and-long-enough-for-pkce";
    let (status, went) = logs_in(at, &root, &node, verifier).await;
    assert_eq!(status, 200, "{went}");
    let went: serde_json::Value = serde_json::from_str(&went).unwrap();
    let location = went["redirect"].as_str().unwrap();
    assert!(location.starts_with(BACK), "{location}");
    assert_eq!(query_of(location, "state"), "the-state");
    let code = query_of(location, "code");

    let (status, token) = ask(
        at,
        "POST",
        "/auth/token",
        token_form(&code, verifier, &node),
    )
    .await;
    assert_eq!(status, 200, "{token}");
    let token: serde_json::Value = serde_json::from_str(&token).unwrap();
    let token = token["access_token"].as_str().unwrap().to_string();
    assert!(
        token.starts_with("qntx_"),
        "QNTX takes no other token: {token}"
    );

    let (status, said) = ask(
        at,
        "POST",
        "/auth/introspect",
        form(&[
            ("token", &token),
            ("client_id", &did(&node)),
            ("client_assertion_type", ASSERTION),
            ("client_assertion", &node_asserts(&node)),
        ]),
    )
    .await;
    assert_eq!(status, 200, "{said}");
    let said: serde_json::Value = serde_json::from_str(&said).unwrap();
    assert_eq!(said["active"], true);
    assert_eq!(said["iss"], ISSUER);
    assert_eq!(said["sub"], did(&root));
    assert_eq!(said["client_id"], did(&node));
    assert_eq!(said["level"], "ROOT", "QNTX's level, as QNTX spells it");

    // A code is spent once.
    let (again, _) = ask(
        at,
        "POST",
        "/auth/token",
        token_form(&code, verifier, &node),
    )
    .await;
    assert_eq!(again, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn somebody_who_is_not_a_root_is_not_sent_back() {
    let root = laye_me::fresh();
    let node = laye_me::fresh();
    let at = laye("stranger", &root, &node).await;
    let stranger = laye_me::fresh();
    let (status, _) = logs_in(
        at,
        &stranger,
        &node,
        "a-verifier-only-qntx-holds-and-long-enough",
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_code_goes_only_to_the_node_that_holds_the_verifier() {
    let root = laye_me::fresh();
    let node = laye_me::fresh();
    let at = laye("verifier", &root, &node).await;
    let (_, went) = logs_in(
        at,
        &root,
        &node,
        "the-verifier-qntx-made-for-this-journey-x",
    )
    .await;
    let went: serde_json::Value = serde_json::from_str(&went).unwrap();
    let code = query_of(went["redirect"].as_str().unwrap(), "code");
    let guessed = "another-verifier-somebody-guessed-at-xxxxxxx";
    let (status, _) = ask(at, "POST", "/auth/token", token_form(&code, guessed, &node)).await;
    assert_eq!(status, 400);
}

/// A node reads who administers the network from laye, signing as itself.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_reads_its_roots_from_laye() {
    let root = laye_me::fresh();
    let node = laye_me::fresh();
    let at = laye("roots", &root, &node).await;
    let asked = form(&[
        ("client_id", &did(&node)),
        ("client_assertion_type", ASSERTION),
        ("client_assertion", &node_asserts(&node)),
    ]);
    let (status, said) = ask(at, "POST", "/laye/roots", asked).await;
    assert_eq!(status, 200, "{said}");
    let said: serde_json::Value = serde_json::from_str(&said).unwrap();
    assert_eq!(said["root_identities"], serde_json::json!([did(&root)]));

    let stranger = laye_me::fresh();
    let asked = form(&[
        ("client_id", &did(&stranger)),
        ("client_assertion_type", ASSERTION),
        ("client_assertion", &node_asserts(&stranger)),
    ]);
    let (status, _) = ask(at, "POST", "/laye/roots", asked).await;
    assert_eq!(status, 401, "a key laye logs nobody in for is told nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_laye_does_not_know_is_sent_nobody() {
    let root = laye_me::fresh();
    let node = laye_me::fresh();
    let at = laye("unknown", &root, &node).await;
    let other = laye_me::fresh();
    let authorize = form(&[
        ("client_id", &did(&other)),
        ("redirect_uri", BACK),
        ("response_type", "code"),
        ("state", "s"),
        ("code_challenge", "c"),
        ("code_challenge_method", "S256"),
    ]);
    let (status, _) = ask(
        at,
        "GET",
        &format!("/auth/authorize?{authorize}"),
        String::new(),
    )
    .await;
    assert_eq!(status, 400);
}
