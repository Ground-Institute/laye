#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "AND LAYE OWNS IDENTITY"
// "QNTX CAN GO DOWN"
// "WHILE LAYE IS STILL THERE"
// "QNTX can be the thing that holds stuff durably"
// "why would it not be able to be many ?"
//
// The authenticator here is software: an ed25519 key answering as a platform
// passkey does, with the flags a person's touch sets. Each test runs a real
// etcd, the `etcd` on PATH or the one $ETCD names, and no QNTX answers.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use bytes::Bytes;
use ciborium::Value;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use laye_front::passkeys::PasskeysAt;
use laye_front::{Config, NamesAt};
use laye_me::{BindingClaim, Keypair, SignedBinding};
use serde_json::json;
use sha2::{Digest, Sha256};
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

fn public(key: &Keypair) -> [u8; 32] {
    key.clone().try_into_ed25519().unwrap().public().to_bytes()
}

fn host(origin: &str) -> &str {
    origin.split_once("://").unwrap().1
}

/// A passkey, as software: its key, its id, and what its counter says next.
struct Authenticator {
    key: Keypair,
    id: Vec<u8>,
    count: u32,
    /// The key the passkey derives on this device (the PRF's).
    owner: Keypair,
}

impl Authenticator {
    fn new() -> Self {
        Authenticator {
            key: laye_me::fresh(),
            id: rand::random::<[u8; 16]>().to_vec(),
            count: 0,
            owner: laye_me::fresh(),
        }
    }

    fn auth_data(&self, flags: u8, with_key: bool) -> Vec<u8> {
        let mut data = Sha256::digest(RP.as_bytes()).to_vec();
        data.push(flags);
        data.extend(self.count.to_be_bytes());
        if with_key {
            data.extend([0u8; 16]);
            data.extend(u16::try_from(self.id.len()).unwrap().to_be_bytes());
            data.extend(&self.id);
            let cose = Value::Map(vec![
                (Value::from(1), Value::from(1)),
                (Value::from(3), Value::from(-8)),
                (Value::from(-1), Value::from(6)),
                (Value::from(-2), Value::Bytes(public(&self.key).to_vec())),
            ]);
            ciborium::into_writer(&cose, &mut data).unwrap();
        }
        data
    }

    fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
        json!({ "type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false })
            .to_string()
            .into_bytes()
    }

    fn owner_proof(&self, challenge: &str) -> serde_json::Value {
        json!({
            "user_did": did(&self.owner),
            "user_did_signature": B64URL.encode(self.owner.sign(challenge.as_bytes()).unwrap()),
        })
    }

    /// navigator.credentials.create, answered.
    fn create(&self, challenge: &str, origin: &str) -> serde_json::Value {
        let auth = self.auth_data(0x01 | 0x04 | 0x40, true);
        let attested = Value::Map(vec![
            (Value::from("fmt"), Value::from("none")),
            (Value::from("attStmt"), Value::Map(Vec::new())),
            (Value::from("authData"), Value::Bytes(auth)),
        ]);
        let mut object = Vec::new();
        ciborium::into_writer(&attested, &mut object).unwrap();
        let mut made = json!({
            "id": B64URL.encode(&self.id),
            "rawId": B64URL.encode(&self.id),
            "type": "public-key",
            "response": {
                "clientDataJSON": B64URL.encode(Self::client_data("webauthn.create", challenge, origin)),
                "attestationObject": B64URL.encode(object),
            },
        });
        made.as_object_mut()
            .unwrap()
            .extend(self.owner_proof(challenge).as_object().unwrap().clone());
        made
    }

    /// navigator.credentials.get, answered, with the person's touch.
    fn get(&mut self, challenge: &str, origin: &str) -> serde_json::Value {
        self.count += 1;
        let auth = self.auth_data(0x01 | 0x04, false);
        let client = Self::client_data("webauthn.get", challenge, origin);
        let mut signed = auth.clone();
        signed.extend(Sha256::digest(&client));
        let mut got = json!({
            "id": B64URL.encode(&self.id),
            "rawId": B64URL.encode(&self.id),
            "type": "public-key",
            "response": {
                "clientDataJSON": B64URL.encode(&client),
                "authenticatorData": B64URL.encode(auth),
                "signature": B64URL.encode(self.key.sign(&signed).unwrap()),
                "userHandle": "",
            },
        });
        got.as_object_mut()
            .unwrap()
            .extend(self.owner_proof(challenge).as_object().unwrap().clone());
        got
    }
}

/// laye's page, proving the browser's key: the challenge laye issued, signed.
async fn first_half(
    front: SocketAddr,
    origin: &str,
    browser: &Keypair,
    bindings: &[SignedBinding],
) -> serde_json::Value {
    let challenge = ask(front, host(origin), "GET", "/laye/challenge", "", "")
        .await
        .unwrap()
        .body["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    json!({
        "did": did(browser),
        "signature": B64URL.encode(browser.sign(challenge.as_bytes()).unwrap()),
        "challenge": challenge,
        "bindings": bindings,
    })
}

/// A passkey made at `origin` for whoever `browser` proves.
async fn enrol(
    front: SocketAddr,
    origin: &str,
    browser: &Keypair,
    bindings: &[SignedBinding],
    passkey: &Authenticator,
) -> Answer {
    let login = first_half(front, origin, browser, bindings).await;
    let begun = ask(
        front,
        host(origin),
        "POST",
        "/laye/passkey/enrol/begin",
        "",
        &login.to_string(),
    )
    .await
    .unwrap();
    assert_eq!(begun.status, 200, "{}", begun.text);
    assert_eq!(begun.body["publicKey"]["rp"]["id"], RP);
    let challenge = begun.body["publicKey"]["challenge"].as_str().unwrap();
    let made = passkey.create(challenge, origin);
    ask(
        front,
        host(origin),
        "POST",
        "/laye/passkey/enrol/finish",
        "",
        &made.to_string(),
    )
    .await
    .unwrap()
}

async fn sign_in(front: SocketAddr, origin: &str, passkey: &mut Authenticator) -> Answer {
    let begun = ask(
        front,
        host(origin),
        "POST",
        "/laye/passkey/signin/begin",
        "",
        "{}",
    )
    .await
    .unwrap();
    assert_eq!(begun.status, 200, "{}", begun.text);
    let challenge = begun.body["publicKey"]["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let got = passkey.get(&challenge, origin);
    ask(
        front,
        host(origin),
        "POST",
        "/laye/passkey/signin/finish",
        "",
        &got.to_string(),
    )
    .await
    .unwrap()
}

async fn kept(etcd: &str, passkey: &Authenticator) -> serde_json::Value {
    let to: SocketAddr = etcd.trim_start_matches("http://").parse().unwrap();
    let key = base64::engine::general_purpose::STANDARD
        .encode(format!("/passkeys/{}", B64URL.encode(&passkey.id)));
    let answer = ask(
        to,
        "127.0.0.1",
        "POST",
        "/v3/kv/range",
        "",
        &json!({ "key": key }).to_string(),
    )
    .await
    .unwrap();
    let value = answer.body["kvs"][0]["value"].as_str().unwrap();
    serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(value)
            .unwrap(),
    )
    .unwrap()
}

fn binding(by: &Keypair, browser: &Keypair, account: &str) -> SignedBinding {
    let claim = BindingClaim {
        peer_pubkey: public(browser),
        provider: "github".into(),
        canonical_id: account.into(),
        handle: Some("onf".into()),
        issued_at: 1,
    };
    SignedBinding {
        signature: by.sign(&claim.canonical_bytes()).unwrap(),
        claim,
        signer_pubkey: public(by),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// "why would it not be able to be many ?"
///
/// A passkey made at one laye signs in at another on the same etcd, at
/// another origin of the same relying party, with no QNTX answering either.
/// The session it makes is the person's, and the cookie alone names them.
#[tokio::test(flavor = "multi_thread")]
async fn made_at_one_laye_and_signed_in_at_another_without_qntx() {
    let etcd = etcd("many").await;
    let browser = laye_me::fresh();
    let roots = vec![did(&browser)];
    let on_q = laye("many-q", &etcd.at, roots.clone(), Vec::new()).await;
    let on_l = laye("many-l", &etcd.at, roots, Vec::new()).await;

    let mut passkey = Authenticator::new();
    let made = enrol(on_q, AT_RP, &browser, &[], &passkey).await;
    assert_eq!(made.status, 200, "{}", made.text);
    assert_eq!(made.body["person"], did(&browser));
    assert_eq!(made.body["level"], "ROOT");

    let record = kept(&etcd.at, &passkey).await;
    assert_eq!(record["person"], did(&browser));
    assert_eq!(record["owners"], json!([did(&passkey.owner)]));

    let signed_in = sign_in(on_l, AT_L, &mut passkey).await;
    assert_eq!(signed_in.status, 200, "{}", signed_in.text);
    let cookie = signed_in.cookie.expect("a session cookie");
    let me = ask(on_l, host(AT_L), "GET", "/laye/passkey/me", &cookie, "")
        .await
        .unwrap();
    assert_eq!(me.status, 200, "{}", me.text);
    assert_eq!(me.body["person"], did(&browser));

    // The relying party names every origin that may ask for its passkeys.
    let related = ask(on_l, RP, "GET", "/.well-known/webauthn", "", "")
        .await
        .unwrap();
    assert_eq!(related.body["origins"], json!([AT_RP, AT_L]));
}

/// The binding that reached the person is asked again at each sign-in, at
/// whichever laye: one that does not trust its signer lets nobody in on it.
#[tokio::test(flavor = "multi_thread")]
async fn a_binding_whose_signer_is_not_trusted_signs_nobody_in() {
    let etcd = etcd("signer").await;
    let node = laye_me::fresh();
    let browser = laye_me::fresh();
    let roots = vec!["github:1739143".to_string()];
    let trusting = laye(
        "signer-q",
        &etcd.at,
        roots.clone(),
        vec![hex(&public(&node))],
    )
    .await;
    let not = laye("signer-l", &etcd.at, roots, Vec::new()).await;

    let mut passkey = Authenticator::new();
    let held = [binding(&node, &browser, "github:1739143")];
    let made = enrol(trusting, AT_RP, &browser, &held, &passkey).await;
    assert_eq!(made.status, 200, "{}", made.text);
    assert_eq!(made.body["person"], "github:1739143");

    let refused = sign_in(not, AT_L, &mut passkey).await;
    assert_eq!(refused.status, 403, "{}", refused.text);
    assert!(refused.cookie.is_none());

    let signed_in = sign_in(trusting, AT_RP, &mut passkey).await;
    assert_eq!(signed_in.status, 200, "{}", signed_in.text);
}

/// A passkey whose counter did not move is a copy, and a ceremony answers once.
#[tokio::test(flavor = "multi_thread")]
async fn a_copied_passkey_and_a_replayed_answer_are_refused() {
    let etcd = etcd("copied").await;
    let browser = laye_me::fresh();
    let on_q = laye("copied-q", &etcd.at, vec![did(&browser)], Vec::new()).await;

    let mut passkey = Authenticator::new();
    assert_eq!(
        enrol(on_q, AT_RP, &browser, &[], &passkey).await.status,
        200
    );

    let begun = ask(on_q, RP, "POST", "/laye/passkey/signin/begin", "", "{}")
        .await
        .unwrap();
    let challenge = begun.body["publicKey"]["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let got = passkey.get(&challenge, AT_RP).to_string();
    let first = ask(on_q, RP, "POST", "/laye/passkey/signin/finish", "", &got)
        .await
        .unwrap();
    assert_eq!(first.status, 200, "{}", first.text);
    let again = ask(on_q, RP, "POST", "/laye/passkey/signin/finish", "", &got)
        .await
        .unwrap();
    assert_eq!(again.status, 401, "{}", again.text);

    passkey.count -= 1;
    let copied = sign_in(on_q, AT_RP, &mut passkey).await;
    assert_eq!(copied.status, 401, "{}", copied.text);
    assert!(copied.text.contains("copied"), "{}", copied.text);
}

/// Nobody laye does not let in makes a passkey, and a passkey answering from
/// an origin laye does not take is refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_makes_no_passkey_and_another_origin_signs_nobody_in() {
    let etcd = etcd("stranger").await;
    let root = laye_me::fresh();
    let on_q = laye("stranger-q", &etcd.at, vec![did(&root)], Vec::new()).await;

    let stranger = laye_me::fresh();
    let login = first_half(on_q, AT_RP, &stranger, &[]).await;
    let begun = ask(
        on_q,
        RP,
        "POST",
        "/laye/passkey/enrol/begin",
        "",
        &login.to_string(),
    )
    .await
    .unwrap();
    assert_eq!(begun.status, 403, "{}", begun.text);

    let mut passkey = Authenticator::new();
    assert_eq!(enrol(on_q, AT_RP, &root, &[], &passkey).await.status, 200);
    let begun = ask(on_q, RP, "POST", "/laye/passkey/signin/begin", "", "{}")
        .await
        .unwrap();
    let challenge = begun.body["publicKey"]["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let got = passkey.get(&challenge, "https://evil.example").to_string();
    let elsewhere = ask(on_q, RP, "POST", "/laye/passkey/signin/finish", "", &got)
        .await
        .unwrap();
    assert_eq!(elsewhere.status, 400, "{}", elsewhere.text);
    assert!(
        elsewhere.text.contains("not an origin"),
        "{}",
        elsewhere.text
    );
}

/// A key signing as itself is no person: laye's session is made by a passkey.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_opens_no_session() {
    let etcd = etcd("key").await;
    let on_q = laye("key-q", &etcd.at, Vec::new(), Vec::new()).await;
    let key = laye_me::fresh();
    let forged = laye_front::jwt::sign(
        &key,
        &laye_front::jwt::Claims {
            iss: did(&key),
            sub: did(&key),
            aud: vec!["laye person".into()],
            exp: u64::MAX / 2,
            jti: laye_front::jwt::fresh_jti(),
            ..Default::default()
        },
    )
    .unwrap();
    let me = ask(
        on_q,
        RP,
        "GET",
        "/laye/passkey/me",
        &format!("laye_person={forged}"),
        "",
    )
    .await
    .unwrap();
    assert_eq!(me.status, 401, "{}", me.text);
}

async fn form(front: SocketAddr, path: &str, authorization: &str, body: &str) -> Answer {
    let stream = tokio::net::TcpStream::connect(front).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let mut req = Request::post(path)
        .header("host", host(AT_L))
        .header("content-type", "application/x-www-form-urlencoded");
    if !authorization.is_empty() {
        req = req.header("authorization", authorization);
    }
    let resp = sender
        .send_request(req.body(Full::new(Bytes::from(body.to_string()))).unwrap())
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let text =
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned();
    Answer {
        status,
        body: serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
        text,
        cookie: None,
    }
}

/// One request's signature by `key`, as itself, for laye's origin.
fn signed(key: &Keypair) -> String {
    let did = did(key);
    let token = laye_front::jwt::sign(
        key,
        &laye_front::jwt::Claims {
            iss: did.clone(),
            sub: did,
            aud: vec![AT_RP.into()],
            exp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
            jti: laye_front::jwt::fresh_jti(),
            ..Default::default()
        },
    )
    .unwrap();
    format!("Signed {token}")
}

/// A key asks at l to be the person's; the person says yes at q, in their
/// passkey session, and nowhere else; the key is then theirs at every laye,
/// and admits a session's key as a key laye's settings name does.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_is_a_persons_once_they_say_yes_with_their_passkey() {
    let etcd = etcd("yes").await;
    let browser = laye_me::fresh();
    let roots = vec![did(&browser)];
    let on_q = laye("yes-q", &etcd.at, roots.clone(), Vec::new()).await;
    let on_l = laye("yes-l", &etcd.at, roots, Vec::new()).await;

    let agent = laye_me::fresh();
    let asked = form(
        on_l,
        "/laye/device",
        "",
        &format!("label=l&did={}", did(&agent).replace(':', "%3A")),
    )
    .await;
    assert_eq!(asked.status, 200, "{}", asked.text);
    let device_code = asked.body["device_code"].as_str().unwrap().to_string();
    let user_code = asked.body["user_code"].as_str().unwrap().to_string();
    assert_eq!(
        asked.body["verification_uri_complete"],
        format!("{AT_RP}/laye/me?user_code={user_code}")
    );

    let pending = form(
        on_l,
        "/laye/device/token",
        "",
        &format!("device_code={device_code}"),
    )
    .await;
    assert_eq!(
        pending.body["error"], "authorization_pending",
        "{}",
        pending.text
    );

    // Nobody without a passkey session says yes, a key signing as itself least.
    let yes = json!({ "user_code": user_code }).to_string();
    let unsigned = ask(on_q, RP, "POST", "/laye/device/approve", "", &yes)
        .await
        .unwrap();
    assert_eq!(unsigned.status, 401, "{}", unsigned.text);

    let mut passkey = Authenticator::new();
    assert_eq!(
        enrol(on_q, AT_RP, &browser, &[], &passkey).await.status,
        200
    );
    let session = sign_in(on_q, AT_RP, &mut passkey).await.cookie.unwrap();
    let shown = ask(
        on_q,
        RP,
        "GET",
        &format!("/laye/device/shown?user_code={}", user_code.to_lowercase()),
        &session,
        "",
    )
    .await
    .unwrap();
    assert_eq!(shown.body["did"], did(&agent), "{}", shown.text);
    let said = ask(on_q, RP, "POST", "/laye/device/approve", &session, &yes)
        .await
        .unwrap();
    assert_eq!(said.status, 200, "{}", said.text);

    let answered = form(
        on_l,
        "/laye/device/token",
        "",
        &format!("device_code={device_code}"),
    )
    .await;
    assert_eq!(answered.status, 200, "{}", answered.text);
    assert_eq!(answered.body["person"], did(&browser));
    assert_eq!(answered.body["did"], did(&agent));
    let again = form(
        on_l,
        "/laye/device/token",
        "",
        &format!("device_code={device_code}"),
    )
    .await;
    assert_eq!(again.status, 400, "{}", again.text);

    // The key the person said yes to admits a session's key, at l.
    let session_key = laye_me::fresh();
    let admitted = form(
        on_l,
        "/auth/admit",
        &signed(&agent),
        &format!("did={}&label=a", did(&session_key).replace(':', "%3A")),
    )
    .await;
    assert_eq!(admitted.status, 200, "{}", admitted.text);
    let stranger = laye_me::fresh();
    let refused = form(
        on_l,
        "/auth/admit",
        &signed(&stranger),
        &format!("did={}&label=b", did(&laye_me::fresh()).replace(':', "%3A")),
    )
    .await;
    assert_eq!(refused.status, 403, "{}", refused.text);
}

async fn signed_get(front: SocketAddr, path: &str, by: &Keypair) -> Answer {
    signed_ask(front, "GET", path, by, "").await
}

async fn signed_ask(
    front: SocketAddr,
    method: &str,
    path: &str,
    by: &Keypair,
    body: &str,
) -> Answer {
    let stream = tokio::net::TcpStream::connect(front).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "api.q.example")
        .header("content-type", "application/json")
        .header("authorization", signed(by))
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let text =
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned();
    Answer {
        status,
        body: serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
        text,
        cookie: None,
    }
}

/// `P2P2A2A_A_001_01`, with no QNTX answering at all.
///
/// "i want laye to also be tht A2A layer collections get placed into and be added or removed from and be released."
///
/// One session says something to another by name. It is collected, and waits;
/// the person releases it in their passkey session; it stands on the row their
/// key polls; the session it was said to takes it, and the Task completes.
#[tokio::test(flavor = "multi_thread")]
async fn one_session_says_to_another_through_laye_and_it_arrives() {
    let etcd = etcd("arrives").await;
    let browser = laye_me::fresh();
    let front = laye("arrives-q", &etcd.at, vec![did(&browser)], Vec::new()).await;

    // The person, in their passkey session.
    let mut passkey = Authenticator::new();
    assert_eq!(
        enrol(front, AT_RP, &browser, &[], &passkey).await.status,
        200
    );
    let session = sign_in(front, AT_RP, &mut passkey).await.cookie.unwrap();

    // ~/.qntx/key, said yes to.
    let qntx_key = laye_me::fresh();
    let asked = form(
        front,
        "/laye/device",
        "",
        &format!("label=laptop&did={}", did(&qntx_key).replace(':', "%3A")),
    )
    .await;
    let yes = json!({ "user_code": asked.body["user_code"] }).to_string();
    let said_yes = ask(front, RP, "POST", "/laye/device/approve", &session, &yes)
        .await
        .unwrap();
    assert_eq!(said_yes.status, 200, "{}", said_yes.text);

    // Two sessions, admitted by it, each named.
    let (alder, birch) = (laye_me::fresh(), laye_me::fresh());
    for (key, name) in [(&alder, "Alder"), (&birch, "Birch")] {
        let admitted = form(
            front,
            "/auth/admit",
            &signed(&qntx_key),
            &format!("did={}&label={name}", did(key).replace(':', "%3A")),
        )
        .await;
        assert_eq!(admitted.status, 200, "{}", admitted.text);
        let named = signed_ask(
            front,
            "POST",
            "/i/name",
            key,
            &json!({ "name": name, "given": "itself" }).to_string(),
        )
        .await;
        assert_eq!(named.status, 200, "{}", named.text);
    }

    // Alder says something to Birch, as ground say does.
    let send = json!({
        "message": { "messageId": "ground-say-1", "role": "ROLE_USER", "parts": [{ "text": "the tide is in" }] },
        "configuration": { "returnImmediately": true },
    });
    let sent = signed_ask(
        front,
        "POST",
        "/a2a/Birch/message:send",
        &alder,
        &send.to_string(),
    )
    .await;
    assert_eq!(sent.status, 200, "{}", sent.text);
    let task = sent.body["task"]["id"].as_str().unwrap().to_string();
    assert_eq!(
        sent.body["task"]["status"]["state"], "TASK_STATE_INPUT_REQUIRED",
        "{}",
        sent.text
    );

    // As ground heard asks.
    let heard = signed_get(front, &format!("/a2a/Birch/tasks/{task}"), &alder).await;
    assert_eq!(
        heard.body["status"]["state"], "TASK_STATE_INPUT_REQUIRED",
        "{}",
        heard.text
    );

    // It waits, for Birch, from Alder; nothing stands on the row yet.
    let waits = ask(front, RP, "GET", "/laye/collected", &session, "")
        .await
        .unwrap();
    assert_eq!(waits.status, 200, "{}", waits.text);
    let one = &waits.body["collected"][0];
    assert_eq!(one["to"], "Birch");
    assert_eq!(one["waiting"][0]["from"], "Alder");
    assert_eq!(one["waiting"][0]["from_did"], did(&alder));
    assert_eq!(one["waiting"][0]["says"], "the tide is in");
    let row = signed_get(front, "/am/statusline?format=json", &qntx_key).await;
    assert_eq!(row.body["items"], json!([]), "{}", row.text);

    // A key never releases: only the person's passkey session.
    let by_key = signed_ask(
        front,
        "POST",
        "/laye/collected/act",
        &qntx_key,
        &json!({ "did": did(&birch), "act": "release" }).to_string(),
    )
    .await;
    assert_ne!(by_key.status, 200, "{}", by_key.text);
    let released = ask(
        front,
        RP,
        "POST",
        "/laye/collected/act",
        &session,
        &json!({ "did": did(&birch), "act": "release" }).to_string(),
    )
    .await
    .unwrap();
    assert_eq!(released.status, 200, "{}", released.text);
    assert_eq!(released.body["waiting"], json!([]));

    // On the person's row, drawn for tmux too, with its id.
    let row = signed_get(front, "/am/statusline?format=json", &qntx_key).await;
    let item = &row.body["items"][0];
    let id = item["id"].as_str().unwrap().to_string();
    assert!(id.len() <= 15, "{id} is longer than a tmux range holds");
    assert!(
        item["note"].as_str().unwrap().contains("the tide is in"),
        "{}",
        row.text
    );
    let drawn = signed_get(front, "/am/statusline?format=tmux", &qntx_key).await;
    assert!(
        drawn.text.contains(&format!("#[range=user|{id}]")),
        "{}",
        drawn.text
    );
    let heard = signed_get(front, &format!("/a2a/Birch/tasks/{task}"), &alder).await;
    assert_eq!(
        heard.body["status"]["state"], "TASK_STATE_WORKING",
        "{}",
        heard.text
    );

    // Alder is the same person's, not Birch: it is answered the whole, as a
    // ground taking it off the row is (QNTX a2a_named.go), and that is not
    // Birch receiving it.
    let not_birch = signed_get(front, &format!("/am/statusline/{id}"), &alder).await;
    assert_eq!(not_birch.status, 200, "{}", not_birch.text);
    let heard = signed_get(front, &format!("/a2a/Birch/tasks/{task}"), &alder).await;
    assert_eq!(
        heard.body["status"]["state"], "TASK_STATE_WORKING",
        "{}",
        heard.text
    );
    // Someone else's key is answered nothing of it.
    let stranger = signed_get(front, &format!("/am/statusline/{id}"), &laye_me::fresh()).await;
    assert_ne!(stranger.status, 200, "{}", stranger.text);

    // Birch asks for the whole of it, as sky does handing it over: received.
    let whole = signed_get(front, &format!("/am/statusline/{id}"), &birch).await;
    assert_eq!(whole.status, 200, "{}", whole.text);
    assert!(
        whole.body["note"]
            .as_str()
            .unwrap()
            .contains("the tide is in")
    );
    let heard = signed_get(front, &format!("/a2a/Birch/tasks/{task}"), &alder).await;
    assert_eq!(
        heard.body["status"]["state"], "TASK_STATE_COMPLETED",
        "{}",
        heard.text
    );
    let row = signed_get(front, "/am/statusline?format=json", &qntx_key).await;
    assert_eq!(row.body["items"], json!([]), "{}", row.text);
}

/// The next event a watch says, within `within`.
async fn next_event(
    body: &mut hyper::body::Incoming,
    within: Duration,
) -> Result<serde_json::Value, String> {
    let deadline = tokio::time::Instant::now() + within;
    let mut said = String::new();
    loop {
        if let Some((event, rest)) = said.split_once("\n\n") {
            let event = event.to_string();
            said = rest.to_string();
            if let Some(data) = event.strip_prefix("data: ") {
                return serde_json::from_str(data).map_err(|e| format!("{data}: {e}"));
            }
            continue;
        }
        let frame = tokio::time::timeout_at(deadline, body.frame())
            .await
            .map_err(|elapsed| {
                format!("no event within {within:?} ({elapsed}); said so far {said:?}")
            })?
            .ok_or("the watch ended")?
            .map_err(|e| e.to_string())?;
        if let Some(data) = frame.data_ref() {
            said.push_str(&String::from_utf8_lossy(data));
        }
    }
}

/// "i see, so it's workable now, but isn't spectacular to demo or be a daily driver, this is very much an early prototype of the core idea."
///
/// A person watching what is collected is told what an agent said as it is
/// said, and not on the next time they ask.
#[tokio::test(flavor = "multi_thread")]
async fn what_an_agent_says_is_pushed_to_the_person_watching() {
    let etcd = etcd("pushed").await;
    let browser = laye_me::fresh();
    let front = laye("pushed-q", &etcd.at, vec![did(&browser)], Vec::new()).await;
    let mut passkey = Authenticator::new();
    assert_eq!(
        enrol(front, AT_RP, &browser, &[], &passkey).await.status,
        200
    );
    let session = sign_in(front, AT_RP, &mut passkey).await.cookie.unwrap();
    let qntx_key = laye_me::fresh();
    let asked = form(
        front,
        "/laye/device",
        "",
        &format!("label=laptop&did={}", did(&qntx_key).replace(':', "%3A")),
    )
    .await;
    let yes = json!({ "user_code": asked.body["user_code"] }).to_string();
    let said_yes = ask(front, RP, "POST", "/laye/device/approve", &session, &yes)
        .await
        .unwrap();
    assert_eq!(said_yes.status, 200, "{}", said_yes.text);
    let (alder, birch) = (laye_me::fresh(), laye_me::fresh());
    for (key, name) in [(&alder, "Alder"), (&birch, "Birch")] {
        let admitted = form(
            front,
            "/auth/admit",
            &signed(&qntx_key),
            &format!("did={}&label={name}", did(key).replace(':', "%3A")),
        )
        .await;
        assert_eq!(admitted.status, 200, "{}", admitted.text);
        let named = signed_ask(
            front,
            "POST",
            "/i/name",
            key,
            &json!({ "name": name, "given": "itself" }).to_string(),
        )
        .await;
        assert_eq!(named.status, 200, "{}", named.text);
    }

    // Nobody's key watches: only the person's session.
    let by_key = signed_get(front, "/laye/collected/watch", &qntx_key).await;
    assert_ne!(by_key.status, 200, "{}", by_key.text);

    let stream = tokio::net::TcpStream::connect(front).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .method("GET")
        .uri("/laye/collected/watch")
        .header("host", RP)
        .header("cookie", &session)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let mut body = resp.into_body();

    // Nothing waits yet: said at once.
    let first = next_event(&mut body, Duration::from_secs(2)).await.unwrap();
    assert_eq!(first["collected"], json!([]), "{first}");

    // Alder says something to Birch: the person is told within a moment.
    let send = json!({
        "message": { "messageId": "ground-say-1", "role": "ROLE_USER", "parts": [{ "text": "the tide is in" }] },
        "configuration": { "returnImmediately": true },
    });
    let sent = signed_ask(
        front,
        "POST",
        "/a2a/Birch/message:send",
        &alder,
        &send.to_string(),
    )
    .await;
    assert_eq!(sent.status, 200, "{}", sent.text);
    let told = next_event(&mut body, Duration::from_secs(2)).await.unwrap();
    assert_eq!(told["collected"][0]["to"], "Birch", "{told}");
    assert_eq!(
        told["collected"][0]["waiting"][0]["says"], "the tide is in",
        "{told}"
    );

    // Released: told that nothing waits any more.
    let released = ask(
        front,
        RP,
        "POST",
        "/laye/collected/act",
        &session,
        &json!({ "did": did(&birch), "act": "release" }).to_string(),
    )
    .await
    .unwrap();
    assert_eq!(released.status, 200, "{}", released.text);
    let after = next_event(&mut body, Duration::from_secs(2)).await.unwrap();
    assert_eq!(after["collected"], json!([]), "{after}");
}

/// A person is shown by their name and photo, as the provider showed them,
/// and laye takes those only with a binding that is that person's.
#[tokio::test(flavor = "multi_thread")]
async fn a_person_is_shown_by_name_and_photo_proven_with_their_binding() {
    let etcd = etcd("shown").await;
    let node = laye_me::fresh();
    let browser = laye_me::fresh();
    let front = laye(
        "shown-q",
        &etcd.at,
        vec!["github:1739143".into()],
        vec![hex(&public(&node))],
    )
    .await;
    let mut passkey = Authenticator::new();
    let held = [binding(&node, &browser, "github:1739143")];
    assert_eq!(
        enrol(front, AT_RP, &browser, &held, &passkey).await.status,
        200
    );
    let session = sign_in(front, AT_RP, &mut passkey).await.cookie.unwrap();

    let shown =
        json!({ "name": "Brandon", "picture": "https://example.com/me.png", "account": "onf" });
    let kept = ask(
        front,
        RP,
        "POST",
        "/laye/person",
        &session,
        &json!({ "binding": held[0], "shown": shown }).to_string(),
    )
    .await
    .unwrap();
    assert_eq!(kept.status, 200, "{}", kept.text);
    let me = ask(front, RP, "GET", "/laye/passkey/me", &session, "")
        .await
        .unwrap();
    assert_eq!(me.body["name"], "Brandon", "{}", me.text);
    assert_eq!(me.body["picture"], "https://example.com/me.png");
    assert!(me.body["until"].as_u64().unwrap() > 0);

    // Someone else's account, or a binding signed by a key laye does not trust, is refused.
    let other = binding(&node, &browser, "github:1");
    let refused = ask(
        front,
        RP,
        "POST",
        "/laye/person",
        &session,
        &json!({ "binding": other, "shown": shown }).to_string(),
    )
    .await
    .unwrap();
    assert_eq!(refused.status, 403, "{}", refused.text);
    let forged = binding(&laye_me::fresh(), &browser, "github:1739143");
    let refused = ask(
        front,
        RP,
        "POST",
        "/laye/person",
        &session,
        &json!({ "binding": forged, "shown": shown }).to_string(),
    )
    .await
    .unwrap();
    assert_eq!(refused.status, 403, "{}", refused.text);
}

// "and we should not show did's the way you show them now"
// "why not show the name"
//
/// What waits is shown from who said it: a session that holds no name, by the
/// label it was admitted under; a key the person said yes to, by the person's
/// name. Never its DID while laye knows any of these.
#[tokio::test(flavor = "multi_thread")]
async fn a_sender_without_a_name_is_shown_by_its_label_or_its_person() {
    let etcd = etcd("called").await;
    let node = laye_me::fresh();
    let browser = laye_me::fresh();
    let front = laye(
        "called-q",
        &etcd.at,
        vec!["github:1739143".into()],
        vec![hex(&public(&node))],
    )
    .await;
    let mut passkey = Authenticator::new();
    let held = [binding(&node, &browser, "github:1739143")];
    assert_eq!(
        enrol(front, AT_RP, &browser, &held, &passkey).await.status,
        200
    );
    let session = sign_in(front, AT_RP, &mut passkey).await.cookie.unwrap();
    let shown = json!({ "name": "Brandon", "picture": "", "account": "onf" });
    let kept = ask(
        front,
        RP,
        "POST",
        "/laye/person",
        &session,
        &json!({ "binding": held[0], "shown": shown }).to_string(),
    )
    .await
    .unwrap();
    assert_eq!(kept.status, 200, "{}", kept.text);

    // ~/.qntx/key, said yes to.
    let qntx_key = laye_me::fresh();
    let asked = form(
        front,
        "/laye/device",
        "",
        &format!("label=laptop&did={}", did(&qntx_key).replace(':', "%3A")),
    )
    .await;
    let yes = json!({ "user_code": asked.body["user_code"] }).to_string();
    let said_yes = ask(front, RP, "POST", "/laye/device/approve", &session, &yes)
        .await
        .unwrap();
    assert_eq!(said_yes.status, 200, "{}", said_yes.text);

    // Birch is named; oak is admitted under a label and holds no name.
    let oak_label = "oak laptop";
    let (birch, oak) = (laye_me::fresh(), laye_me::fresh());
    for (key, label) in [(&birch, "Birch"), (&oak, oak_label)] {
        let admitted = form(
            front,
            "/auth/admit",
            &signed(&qntx_key),
            &format!(
                "did={}&label={}",
                did(key).replace(':', "%3A"),
                label.replace(' ', "+")
            ),
        )
        .await;
        assert_eq!(admitted.status, 200, "{}", admitted.text);
    }
    let named = signed_ask(
        front,
        "POST",
        "/i/name",
        &birch,
        &json!({ "name": "Birch" }).to_string(),
    )
    .await;
    assert_eq!(named.status, 200, "{}", named.text);

    for (n, from) in [&oak, &qntx_key].into_iter().enumerate() {
        let send = json!({
            "message": { "messageId": format!("called-{n}"), "role": "ROLE_USER", "parts": [{ "text": "hello" }] },
            "configuration": { "returnImmediately": true },
        });
        let sent = signed_ask(
            front,
            "POST",
            "/a2a/Birch/message:send",
            from,
            &send.to_string(),
        )
        .await;
        assert_eq!(sent.status, 200, "{}", sent.text);
    }

    let waits = ask(front, RP, "GET", "/laye/collected", &session, "")
        .await
        .unwrap();
    assert_eq!(waits.status, 200, "{}", waits.text);
    // What each said to Birch is a collection of its own, named for who said it.
    let collected = waits.body["collected"].as_array().unwrap();
    assert_eq!(collected.len(), 2, "{}", waits.text);
    let mut from: Vec<(&str, &str)> = collected
        .iter()
        .map(|c| {
            (
                c["from"].as_str().unwrap(),
                c["waiting"][0]["from"].as_str().unwrap(),
            )
        })
        .collect();
    from.sort_unstable();
    assert_eq!(
        from,
        [("Brandon", "Brandon"), (oak_label, oak_label)],
        "{}",
        waits.text
    );
}
