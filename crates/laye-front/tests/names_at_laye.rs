#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "I WANT A SESSION TO BE ABLE TO GIVE ITSELF AN AVAILABLE NAME, AMONGST ALL PARTICIPANTS IN THE CLUSTER"
// "SO, ONE ALDER"
// "ONE SLATE"
// "QNTX CAN GO DOWN"
// "WHILE LAYE IS STILL THERE"
// "I'd put names under /names/ there from the start,"
//
// Each test runs a real etcd: the `etcd` on PATH, or the one $ETCD names.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use laye_front::{Config, NamesAt, jwt};
use tokio::net::TcpListener;

const PUBLIC: &str = "https://api.q.example";
const QNTX_DID: &str = "did:key:z6MkqntxNodeStandsHere";

/// etcd, run for one test and stopped with it.
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
    let dir = std::env::temp_dir().join(format!("laye-names-{name}-{}", std::process::id()));
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
        if let Ok((200, body)) = post(
            client,
            "/v3/kv/range",
            "",
            "application/json",
            r#"{"key":"AA=="}"#,
        )
        .await
            && body.contains("header")
        {
            return etcd;
        }
        assert!(Instant::now() < deadline, "etcd at {client} never answered");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[derive(Clone, Debug)]
struct Arrived {
    path: String,
    authorization: String,
    body: Vec<u8>,
}

/// A QNTX that keeps what arrives and answers yes.
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
                let service =
                    hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
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
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"{}"))))
                        }
                    });
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

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn config(qntx: SocketAddr, dir: &std::path::Path, etcd: &str, admitters: Vec<String>) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        qntx: format!("http://{qntx}"),
        qntx_did: QNTX_DID.into(),
        public_origins: vec![PUBLIC.into()],
        root_identities: Vec::new(),
        binding_signers: Vec::new(),
        issuer: "https://laye.example".into(),
        nodes: Vec::new(),
        invitations_at: dir.join("invitations.jsonl"),
        ceremony_at: "https://node.example".into(),
        held_at: dir.join("held.jsonl"),
        names: Some(NamesAt {
            etcd: etcd.into(),
            admitters,
        }),
    }
}

fn did(key: &laye_me::Keypair) -> String {
    laye_peer::did_of(key).unwrap()
}

/// One request's signature by `key`, as itself, for the public origin.
fn signed(key: &laye_me::Keypair) -> String {
    let did = did(key);
    let token = jwt::sign(
        key,
        &jwt::Claims {
            iss: did.clone(),
            sub: did,
            aud: vec![PUBLIC.into()],
            exp: now() + 60,
            jti: jwt::fresh_jti(),
            ..Default::default()
        },
    )
    .unwrap();
    format!("Signed {token}")
}

async fn post(
    to: SocketAddr,
    path: &str,
    authorization: &str,
    kind: &str,
    body: &str,
) -> Result<(u16, String), String> {
    let stream = tokio::net::TcpStream::connect(to)
        .await
        .map_err(|e| e.to_string())?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let mut req = Request::post(path)
        .header("host", "api.q.example")
        .header("content-type", kind);
    if !authorization.is_empty() {
        req = req.header("authorization", authorization);
    }
    let resp = sender
        .send_request(req.body(Full::new(Bytes::from(body.to_string()))).unwrap())
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

/// ~/.qntx/key admits the session's key, as ground does.
async fn admit(
    front: SocketAddr,
    by: &laye_me::Keypair,
    session: &laye_me::Keypair,
    label: &str,
) -> (u16, String) {
    let form = format!("did={}&label={label}", did(session).replace(':', "%3A"));
    post(
        front,
        "/auth/admit",
        &signed(by),
        "application/x-www-form-urlencoded",
        &form,
    )
    .await
    .unwrap()
}

/// The session names itself, by its own key, as ground does.
async fn name(front: SocketAddr, session: &laye_me::Keypair, wanted: &str) -> (u16, String) {
    let body = format!(r#"{{"name":"{wanted}","given":"itself"}}"#);
    post(
        front,
        "/i/name",
        &signed(session),
        "application/json",
        &body,
    )
    .await
    .unwrap()
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// "SO, ONE ALDER"
///
/// A name is one session's, asked of any laye that keeps names in the same
/// etcd.
#[tokio::test(flavor = "multi_thread")]
async fn one_alder_amongst_every_laye_on_one_etcd() {
    let etcd = etcd("one").await;
    let person = laye_me::fresh();
    let qntx = free_addr().await;
    let (on_l, _l) = laye_front::start(
        config(qntx, &scratch("one-l"), &etcd.at, vec![did(&person)]),
        laye_me::fresh(),
    )
    .await
    .unwrap();
    let (on_k, _k) = laye_front::start(
        config(qntx, &scratch("one-k"), &etcd.at, vec![did(&person)]),
        laye_me::fresh(),
    )
    .await
    .unwrap();

    let alder = laye_me::fresh();
    let other = laye_me::fresh();
    assert_eq!(admit(on_l.addr, &person, &alder, "a").await.0, 200);
    assert_eq!(admit(on_k.addr, &person, &other, "b").await.0, 200);

    let (status, body) = name(on_l.addr, &alder, "Alder").await;
    assert_eq!(status, 200, "{body}");
    let answer: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(answer["name"], "Alder");
    assert_eq!(answer["did"], did(&alder));

    // At the other laye, in any case of its letters.
    let (status, body) = name(on_k.addr, &other, "Alder").await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("is taken"), "{body}");
    assert_eq!(name(on_k.addr, &other, "Alder Alder").await.0, 200);

    // Asked again, the name it holds is answered again.
    assert_eq!(name(on_k.addr, &alder, "Alder").await.0, 200);
}

/// A session that takes another name lets go of the one it held.
#[tokio::test(flavor = "multi_thread")]
async fn a_name_left_is_free_for_another() {
    let etcd = etcd("left").await;
    let person = laye_me::fresh();
    let qntx = free_addr().await;
    let (front, _run) = laye_front::start(
        config(qntx, &scratch("left"), &etcd.at, vec![did(&person)]),
        laye_me::fresh(),
    )
    .await
    .unwrap();
    let first = laye_me::fresh();
    let second = laye_me::fresh();
    admit(front.addr, &person, &first, "a").await;
    admit(front.addr, &person, &second, "b").await;

    assert_eq!(name(front.addr, &first, "Alder").await.0, 200);
    assert_eq!(name(front.addr, &second, "Alder").await.0, 403);
    assert_eq!(name(front.addr, &first, "Slate").await.0, 200);
    assert_eq!(name(front.addr, &second, "Alder").await.0, 200);
    assert_eq!(name(front.addr, &second, "Slate").await.0, 403);
}

/// Many sessions asking for one name at once, at three laye: one holds it.
#[tokio::test(flavor = "multi_thread")]
async fn asked_at_once_one_holds_it() {
    let etcd = etcd("once").await;
    let person = laye_me::fresh();
    let qntx = free_addr().await;
    let mut fronts = Vec::new();
    for at in ["once-l", "once-k", "once-q"] {
        let (front, run) = laye_front::start(
            config(qntx, &scratch(at), &etcd.at, vec![did(&person)]),
            laye_me::fresh(),
        )
        .await
        .unwrap();
        fronts.push((front.addr, run));
    }
    let sessions: Vec<laye_me::Keypair> = (0..12).map(|_| laye_me::fresh()).collect();
    for (i, session) in sessions.iter().enumerate() {
        assert_eq!(admit(fronts[i % 3].0, &person, session, "s").await.0, 200);
    }
    let asked: Vec<_> = sessions
        .iter()
        .enumerate()
        .map(|(i, session)| {
            let at = fronts[i % 3].0;
            let session = session.clone();
            tokio::spawn(async move { name(at, &session, "Rowan").await })
        })
        .collect();
    let mut held = 0;
    for answer in asked {
        let (status, body) = answer.await.unwrap();
        match status {
            200 => held += 1,
            403 => assert!(body.contains("is taken"), "{body}"),
            other => panic!("{other}: {body}"),
        }
    }
    assert_eq!(held, 1);
}

/// Only a key laye's settings name admits a session's key, and a session no
/// such key admitted names nothing.
#[tokio::test(flavor = "multi_thread")]
async fn only_the_key_said_yes_to_admits() {
    let etcd = etcd("admit").await;
    let person = laye_me::fresh();
    let qntx = free_addr().await;
    let (front, _run) = laye_front::start(
        config(qntx, &scratch("admit"), &etcd.at, vec![did(&person)]),
        laye_me::fresh(),
    )
    .await
    .unwrap();
    let stranger = laye_me::fresh();
    let session = laye_me::fresh();

    assert_eq!(admit(front.addr, &stranger, &session, "s").await.0, 403);
    let (status, body) = name(front.addr, &session, "Alder").await;
    assert_eq!(status, 401, "{body}");

    assert_eq!(admit(front.addr, &person, &session, "s").await.0, 200);
    assert_eq!(admit(front.addr, &person, &session, "s").await.0, 409);
    assert_eq!(admit(front.addr, &person, &person, "s").await.0, 400);

    // What is no name, as QNTX holds it.
    for wanted in ["alder", "Alder2", "Root", "Brr"] {
        assert_eq!(name(front.addr, &session, wanted).await.0, 400, "{wanted}");
    }
    // Unsigned.
    let (status, _) = post(
        front.addr,
        "/i/name",
        "",
        "application/json",
        r#"{"name":"Alder"}"#,
    )
    .await
    .unwrap();
    assert_eq!(status, 401);
}

/// "QNTX CAN GO DOWN"
/// "WHILE LAYE IS STILL THERE"
///
/// With QNTX down, a session is admitted and named; QNTX is told of both, by
/// laye, once it is back.
#[tokio::test(flavor = "multi_thread")]
async fn named_while_qntx_is_down_and_qntx_is_told() {
    let etcd = etcd("down").await;
    let person = laye_me::fresh();
    let laye_key = laye_me::fresh();
    let qntx = free_addr().await;
    let (front, _run) = laye_front::start(
        config(qntx, &scratch("down"), &etcd.at, vec![did(&person)]),
        laye_key.clone(),
    )
    .await
    .unwrap();
    let session = laye_me::fresh();
    assert_eq!(admit(front.addr, &person, &session, "a").await.0, 200);
    let (status, body) = name(front.addr, &session, "Slate").await;
    assert_eq!(status, 200, "{body}");

    let arrived = Arc::new(Mutex::new(Vec::new()));
    let _qntx = qntx_at(qntx, arrived.clone()).await;
    until("QNTX was never told", || arrived.lock().unwrap().len() == 2).await;

    let got = arrived.lock().unwrap().clone();
    assert_eq!(got[0].path, "/auth/admit");
    let claims = jwt::read(got[0].authorization.strip_prefix("Signed ").unwrap()).unwrap();
    assert_eq!(claims.iss, did(&laye_key));
    assert_eq!(claims.sub, did(&person));
    assert_eq!(got[1].path, "/i/name");
    assert_eq!(got[1].body, br#"{"name":"Slate","given":"itself"}"#);
    let claims = jwt::read(got[1].authorization.strip_prefix("Signed ").unwrap()).unwrap();
    assert_eq!(claims.sub, did(&session));
}

/// A session admitted at one laye is admitted again at another on the same
/// etcd: laye answers it is held, and that other laye's QNTX is told of it.
#[tokio::test(flavor = "multi_thread")]
async fn an_admission_held_elsewhere_is_told_to_this_qntx() {
    let etcd = etcd("held").await;
    let person = laye_me::fresh();
    let (on_l, _l) = laye_front::start(
        config(
            free_addr().await,
            &scratch("held-l"),
            &etcd.at,
            vec![did(&person)],
        ),
        laye_me::fresh(),
    )
    .await
    .unwrap();
    let k_qntx = free_addr().await;
    let arrived = Arc::new(Mutex::new(Vec::new()));
    let _qntx = qntx_at(k_qntx, arrived.clone()).await;
    let (on_k, _k) = laye_front::start(
        config(k_qntx, &scratch("held-k"), &etcd.at, vec![did(&person)]),
        laye_me::fresh(),
    )
    .await
    .unwrap();
    let session = laye_me::fresh();

    assert_eq!(admit(on_l.addr, &person, &session, "a").await.0, 200);
    assert_eq!(admit(on_k.addr, &person, &session, "a").await.0, 409);
    until("k's QNTX was never told", || {
        arrived
            .lock()
            .unwrap()
            .iter()
            .any(|a| a.path == "/auth/admit")
    })
    .await;
}
