#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "the network is invite only"
// "and i own the invites"
// "and i can kick anyone off for whatever reason"
// "for inviting someone, the user story already exists in a way"

// QNTX-Web stories/1-root-invites-a-user.feature, at laye.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use laye_front::{Config, Node, jwt};
use laye_me::{BindingClaim, SignedBinding};

const ISSUER: &str = "https://laye.example";
const BACK: &str = "https://node.example/auth/elsewhere/back";
const ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const VERIFIER: &str = "a-verifier-only-qntx-holds-and-long-enough-for-pkce";

struct World {
    at: SocketAddr,
    root: laye_me::Keypair,
    node: laye_me::Keypair,
    /// What vouches for an account: the provider ceremony's key.
    signer: laye_me::Keypair,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn did(key: &laye_me::Keypair) -> String {
    laye_peer::did_of(key).unwrap()
}

fn public(key: &laye_me::Keypair) -> [u8; 32] {
    key.public().try_into_ed25519().unwrap().to_bytes()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn world(name: &str) -> World {
    let root = laye_me::fresh();
    let node = laye_me::fresh();
    let signer = laye_me::fresh();
    let dir = std::env::temp_dir().join(format!("laye-invites-{name}-{}", std::process::id()));
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    }
    std::fs::create_dir_all(&dir).unwrap();
    let (front, run) = laye_front::start(
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            qntx: "http://127.0.0.1:9".into(),
            qntx_did: did(&node),
            public_origins: vec![ISSUER.into()],
            held_at: dir.join("held.jsonl"),
            root_identities: vec![did(&root)],
            binding_signers: vec![hex(&public(&signer))],
            issuer: ISSUER.into(),
            nodes: vec![Node {
                did: did(&node),
                back: BACK.into(),
            }],
            invitations_at: dir.join("invitations.jsonl"),
            ceremony_at: "https://node.example".into(),
            names: None,
            passkeys: None,
            web: None,
        },
        laye_me::fresh(),
    )
    .await
    .unwrap();
    std::mem::forget(run);
    World {
        at: front.addr,
        root,
        node,
        signer,
    }
}

async fn ask(
    at: SocketAddr,
    method: &str,
    path: &str,
    auth: Option<String>,
    body: String,
) -> (u16, String) {
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
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "laye.example")
        .header("content-type", content_type);
    if let Some(auth) = auth {
        req = req.header("authorization", auth);
    }
    let resp = sender
        .send_request(req.body(Full::new(Bytes::from(body))).unwrap())
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn encode(s: &str) -> String {
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
        .map(|(k, v)| format!("{k}={}", encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// A key signing as itself, for laye.
fn signed_by(key: &laye_me::Keypair) -> String {
    let token = jwt::sign(
        key,
        &jwt::Claims {
            iss: did(key),
            sub: did(key),
            aud: vec![ISSUER.into()],
            exp: now() + 60,
            jti: jwt::fresh_jti(),
            ..Default::default()
        },
    )
    .unwrap();
    format!("Signed {token}")
}

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

/// The friend's browser key, and the provider ceremony vouching that it holds
/// this account.
fn friend_holding(w: &World, provider: &str, account: &str) -> (laye_me::Keypair, SignedBinding) {
    let device = laye_me::fresh();
    let claim = BindingClaim {
        peer_pubkey: public(&device),
        provider: provider.into(),
        canonical_id: account.into(),
        handle: None,
        issued_at: now(),
    };
    let binding = SignedBinding {
        signature: w.signer.sign(&claim.canonical_bytes()).unwrap(),
        signer_pubkey: public(&w.signer),
        claim,
    };
    (device, binding)
}

/// The friend comes through the node to laye's screen and signs in. Some is
/// the token the node is handed, None is laye refusing.
async fn signs_in(w: &World, device: &laye_me::Keypair, binding: &SignedBinding) -> Option<String> {
    use sha2::Digest;
    let challenge = B64URL.encode(sha2::Sha256::digest(VERIFIER.as_bytes()));
    let authorize = form(&[
        ("client_id", &did(&w.node)),
        ("redirect_uri", BACK),
        ("response_type", "code"),
        ("state", "s"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]);
    let (_, issued) = ask(w.at, "GET", "/laye/challenge", None, String::new()).await;
    let issued: serde_json::Value = serde_json::from_str(&issued).unwrap();
    let said = issued["challenge"].as_str().unwrap().to_string();
    let login = serde_json::json!({
        "did": did(device),
        "signature": B64URL.encode(device.sign(said.as_bytes()).unwrap()),
        "challenge": said,
        "bindings": [binding],
        "authorize": authorize,
    });
    let (status, went) = ask(w.at, "POST", "/laye/login", None, login.to_string()).await;
    if status != 200 {
        return None;
    }
    let went: serde_json::Value = serde_json::from_str(&went).unwrap();
    let location = went["redirect"].as_str().unwrap();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();
    let (_, token) = ask(
        w.at,
        "POST",
        "/auth/token",
        None,
        form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", BACK),
            ("code_verifier", VERIFIER),
            ("client_id", &did(&w.node)),
            ("client_assertion_type", ASSERTION),
            ("client_assertion", &node_asserts(&w.node)),
        ]),
    )
    .await;
    let token: serde_json::Value = serde_json::from_str(&token).unwrap();
    Some(token["access_token"].as_str().unwrap().to_string())
}

/// What laye tells the node a token is.
async fn who_is(w: &World, token: &str) -> serde_json::Value {
    let (_, said) = ask(
        w.at,
        "POST",
        "/auth/introspect",
        None,
        form(&[
            ("token", token),
            ("client_id", &did(&w.node)),
            ("client_assertion_type", ASSERTION),
            ("client_assertion", &node_asserts(&w.node)),
        ]),
    )
    .await;
    serde_json::from_str(&said).unwrap()
}

async fn invite(
    w: &World,
    by: &laye_me::Keypair,
    provider: &str,
    account: &str,
) -> (u16, serde_json::Value) {
    let asked = serde_json::json!({ "accounts": [{ "provider": provider, "account": account }] });
    let (status, said) = ask(
        w.at,
        "POST",
        "/laye/invitations",
        Some(signed_by(by)),
        asked.to_string(),
    )
    .await;
    (status, serde_json::from_str(&said).unwrap_or_default())
}

async fn withdraw(w: &World, id: &str) -> u16 {
    let asked = serde_json::json!({ "id": id });
    ask(
        w.at,
        "POST",
        "/laye/invitations/withdraw",
        Some(signed_by(&w.root)),
        asked.to_string(),
    )
    .await
    .0
}

#[tokio::test(flavor = "multi_thread")]
async fn root_invites_a_friend_and_the_friend_signs_in_with_the_account_root_named() {
    let w = world("invite").await;
    let (status, inv) = invite(&w, &w.root, "github", "github:42").await;
    assert_eq!(status, 200, "{inv}");
    assert_eq!(inv["invited_by"], did(&w.root));

    let (device, binding) = friend_holding(&w, "github", "github:42");
    let token = signs_in(&w, &device, &binding)
        .await
        .expect("the friend was not let in");
    let said = who_is(&w, &token).await;
    assert_eq!(said["active"], true);
    assert_eq!(said["sub"], "github:42");
    assert_eq!(said["level"], "USER", "a friend is a user, not a root");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_account_nobody_invited_is_not_let_in() {
    let w = world("uninvited").await;
    invite(&w, &w.root, "github", "github:42").await;
    let (device, binding) = friend_holding(&w, "github", "github:7");
    assert!(signs_in(&w, &device, &binding).await.is_none());
    let (device, binding) = friend_holding(&w, "google", "github:42");
    assert!(
        signs_in(&w, &device, &binding).await.is_none(),
        "the same name at another provider is somebody else"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn root_cancels_the_invitation_and_the_friend_is_not_let_in() {
    let w = world("cancel").await;
    let (_, inv) = invite(&w, &w.root, "github", "github:42").await;
    assert_eq!(withdraw(&w, inv["id"].as_str().unwrap()).await, 200);
    let (device, binding) = friend_holding(&w, "github", "github:42");
    assert!(signs_in(&w, &device, &binding).await.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn root_kicks_a_friend_who_got_in_and_their_token_stops() {
    let w = world("kick").await;
    let (_, inv) = invite(&w, &w.root, "github", "github:42").await;
    let (device, binding) = friend_holding(&w, "github", "github:42");
    let token = signs_in(&w, &device, &binding).await.unwrap();
    assert_eq!(who_is(&w, &token).await["active"], true);

    assert_eq!(withdraw(&w, inv["id"].as_str().unwrap()).await, 200);
    assert_eq!(
        who_is(&w, &token).await["active"],
        false,
        "a kicked friend's token still stands"
    );
    let (device, binding) = friend_holding(&w, "github", "github:42");
    assert!(
        signs_in(&w, &device, &binding).await.is_none(),
        "a kicked friend signed in again"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_a_root_invites() {
    let w = world("only-root").await;
    let stranger = laye_me::fresh();
    let (status, _) = invite(&w, &stranger, "github", "github:42").await;
    assert_eq!(status, 403);
    let asked =
        serde_json::json!({ "accounts": [{ "provider": "github", "account": "github:42" }] });
    let (status, _) = ask(w.at, "POST", "/laye/invitations", None, asked.to_string()).await;
    assert_eq!(status, 401);
}
