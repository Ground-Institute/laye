#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "1. but laye could use QNTX to send mail."
// "right, and QNTX mail allows you to set a custom template, try to make it fit laye theme"
// "A mail actually goes out to both me and my friend"

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use laye_front::{Config, jwt};
use tokio::net::TcpListener;

const ISSUER: &str = "https://laye.example";
const ROOT: &str = "google:110106507016968762213";

#[derive(Clone)]
struct Asked {
    path: String,
    authorization: String,
    body: serde_json::Value,
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

/// A QNTX that keeps what laye asks of it and says it mailed it.
async fn qntx(asked: Arc<Mutex<Vec<Asked>>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let asked = asked.clone();
            tokio::spawn(async move {
                let service =
                    hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        let asked = asked.clone();
                        async move {
                            let path = req.uri().path().to_string();
                            let authorization = req
                                .headers()
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or_default()
                                .to_string();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            asked.lock().unwrap().push(Asked {
                                path,
                                authorization,
                                body: serde_json::from_slice(&body).unwrap_or_default(),
                            });
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                br#"{"mailed":"tim@example.com"}"#,
                            ))))
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
    });
    addr
}

struct World {
    at: SocketAddr,
    laye: laye_me::Keypair,
    node: laye_me::Keypair,
}

async fn world(name: &str, qntx: String) -> World {
    let laye = laye_me::fresh();
    let node = laye_me::fresh();
    let dir = std::env::temp_dir().join(format!("laye-mailed-{name}-{}", std::process::id()));
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    }
    std::fs::create_dir_all(&dir).unwrap();
    let (front, run) = laye_front::start(
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            qntx,
            qntx_did: did(&node),
            public_origins: vec![ISSUER.into()],
            held_at: dir.join("held.jsonl"),
            root_identities: vec![ROOT.into()],
            binding_signers: Vec::new(),
            issuer: ISSUER.into(),
            nodes: Vec::new(),
            invitations_at: dir.join("invitations.jsonl"),
            ceremony_at: "https://node.example".into(),
            names: None,
            passkeys: None,
            web: None,
            apns: None,
            pack_nodes: Vec::new(),
            governed: None,
        },
        laye.clone(),
    )
    .await
    .unwrap();
    std::mem::forget(run);
    World {
        at: front.addr,
        laye,
        node,
    }
}

/// The root, pressing Invite on laye's page.
async fn invites(w: &World, body: serde_json::Value) -> (u16, serde_json::Value) {
    let session = jwt::sign(
        &w.laye,
        &jwt::Claims {
            iss: did(&w.laye),
            sub: ROOT.into(),
            aud: vec!["laye person".into()],
            exp: now() + 600,
            iat: now(),
            jti: jwt::fresh_jti(),
            label: "ROOT".into(),
        },
    )
    .unwrap();
    let stream = tokio::net::TcpStream::connect(w.at).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::post("/laye/invitations")
        .header("host", "laye.example")
        .header("content-type", "application/json")
        .header("cookie", format!("laye_person={session}"))
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let said = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&said).unwrap())
}

fn friend() -> serde_json::Value {
    serde_json::json!({
        "accounts": [{ "provider": "github", "account": "github:42" }],
        "email": "tim@example.com",
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_is_mailed_by_qntx_in_layes_look() {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let qntx = qntx(asked.clone()).await;
    let w = world("mailed", format!("http://{qntx}")).await;

    let (status, inv) = invites(&w, friend()).await;
    assert_eq!(status, 200, "{inv}");
    assert_eq!(inv["email"], "tim@example.com");
    assert_eq!(inv["mailed"], "tim@example.com", "{inv}");

    let got = asked.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].path, "/auth/laye/invited");
    let claims = jwt::read(got[0].authorization.strip_prefix("Signed ").unwrap()).unwrap();
    assert_eq!(claims.iss, did(&w.laye), "laye signs as itself");
    assert_eq!(claims.sub, did(&w.laye));
    assert_eq!(claims.aud, vec![did(&w.node)], "for QNTX alone");

    let body = &got[0].body;
    assert_eq!(body["invitation"], inv["id"]);
    assert_eq!(body["email"], "tim@example.com");
    assert_eq!(body["invited_by"], ROOT);
    assert_eq!(
        body["friend"]["values"]["link"],
        format!("{ISSUER}/laye/me")
    );
    let cancel = format!("{ISSUER}/laye/me?cancel={}", inv["id"].as_str().unwrap());
    assert_eq!(body["root"]["values"]["link"], cancel);
    let html = body["friend"]["template"]["html"].as_str().unwrap();
    assert!(html.contains("#050608"), "the mail is laye's night");
    assert!(html.contains("{{.link}}"), "QNTX fills the template");
}

#[tokio::test(flavor = "multi_thread")]
async fn while_qntx_is_down_the_invitation_stands_and_says_it_was_not_mailed() {
    let w = world("down", "http://127.0.0.1:9".into()).await;
    let (status, inv) = invites(&w, friend()).await;
    assert_eq!(status, 200, "{inv}");
    assert!(inv["mail_error"].is_string(), "{inv}");
    assert!(inv.get("mailed").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_with_no_address_asks_qntx_for_nothing() {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let qntx = qntx(asked.clone()).await;
    let w = world("no-address", format!("http://{qntx}")).await;
    let mut body = friend();
    body.as_object_mut().unwrap().remove("email");
    let (status, inv) = invites(&w, body).await;
    assert_eq!(status, 200, "{inv}");
    assert!(asked.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_address_that_is_not_one_is_refused() {
    let w = world("bad-address", "http://127.0.0.1:9".into()).await;
    let mut body = friend();
    body["email"] = "not an address".into();
    let (status, _) = invites(&w, body).await;
    assert_eq!(status, 400);
}
