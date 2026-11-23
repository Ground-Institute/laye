#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "yeah, because right now, i dont even see the outgoing towards node agent in ag right? yeah thats fucked up as well"
// "yes, you move that to laye too"
//
// What QNTX hands laye for its own agent waits beside everything else on the
// person, and once released is news laye hands back to QNTX. Each test runs a
// real etcd, the `etcd` on PATH or the one $ETCD names.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use laye_front::collected::{Act, Collections, NEWS, News, Whose};
use laye_front::etcd::Etcd as Store;
use tokio::net::TcpListener;

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

// The same answer the other tests read; here only its status, while etcd starts.
#[allow(dead_code)]
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

fn store(at: &str) -> Store {
    Store::new(at, Client::builder(TokioExecutor::new()).build_http())
}

const LAYE: &str = "did:key:z6MkLayeHere";
const LAMPLIGHTER: &str = "did:key:z6MkLamplighter";
const PERSON: &str = "google:110106507016968762213";

#[tokio::test]
async fn what_is_released_for_the_nodes_agent_is_news_laye_hands_back() {
    let etcd = etcd("node-agent").await;
    let kv = store(&etcd.at);
    let held = Collections {
        etcd: &kv,
        laye: LAYE,
    };
    let whose = Whose {
        person: PERSON.into(),
        node: true,
        quiet: false,
    };
    held.collect(
        LAMPLIGHTER,
        "Lamplighter",
        "did:key:z6MkAlder",
        "Alder",
        "the build is green",
        "c1",
        &whose,
        1_795_000_000,
    )
    .await
    .unwrap();
    let all = held.all().await.unwrap();
    let waits = all.iter().find(|c| c.did == LAMPLIGHTER).unwrap();
    assert!(waits.node);
    assert_eq!(waits.person, PERSON);

    held.act(
        LAMPLIGHTER,
        &Act::Release {
            ids: Vec::new(),
            says: None,
        },
        PERSON,
        1_795_000_060,
    )
    .await
    .unwrap();
    let news: Vec<News> = kv
        .under(NEWS)
        .await
        .unwrap()
        .into_iter()
        .map(|(_, kv)| serde_json::from_slice(&kv.value).unwrap())
        .collect();
    assert_eq!(news.len(), 1);
    assert!(
        news[0].node,
        "what was released for the node's agent is not marked the node's"
    );
    assert_eq!(news[0].for_person, PERSON);
    assert_eq!(news[0].did, LAMPLIGHTER);
    assert!(news[0].note.contains("the build is green"));
}

#[tokio::test]
async fn what_wakes_nobody_is_never_due_by_itself() {
    let etcd = etcd("quiet").await;
    let kv = store(&etcd.at);
    let held = Collections {
        etcd: &kv,
        laye: LAYE,
    };
    let quiet = Whose {
        person: PERSON.into(),
        node: true,
        quiet: true,
    };
    held.collect(
        LAMPLIGHTER,
        "Lamplighter",
        "did:key:z6MkNode",
        "GitHub",
        "#1 merged",
        "c2",
        &quiet,
        1_795_000_000,
    )
    .await
    .unwrap();
    // Long past any wait: what wakes nobody is still not delivered.
    assert!(held.deliver_due(1_795_000_000 + 86_400).await.is_empty());
    assert!(
        kv.under(NEWS).await.unwrap().is_empty(),
        "a quiet thing alone was delivered"
    );
    let all = held.all().await.unwrap();
    assert_eq!(
        all.iter()
            .find(|c| c.did == LAMPLIGHTER)
            .unwrap()
            .waiting
            .len(),
        1
    );
}
