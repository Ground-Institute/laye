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
        None,
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

// "i expect in my mentalmodel to have multiple pending individual collections"
// "two Keeper messages, i change one time and both change"
//
// A collection is what one agent said to one other, and its own: with its own
// time, held and released by itself.

const KEEPER: &str = "did:key:z6MkKeeper";
const ALDER: &str = "did:key:z6MkAlder";
const BIRCH: &str = "did:key:z6MkBirch";
const T0: u64 = 1_795_000_000;

async fn says(held: &Collections<'_>, from_did: &str, from: &str, says: &str, at: u64) {
    held.collect(
        KEEPER,
        "Keeper",
        from_did,
        from,
        says,
        "c",
        &Whose {
            person: PERSON.into(),
            ..Whose::default()
        },
        at,
    )
    .await
    .unwrap();
}

async fn for_keeper(held: &Collections<'_>) -> Vec<laye_front::collected::Collected> {
    let mut all: Vec<_> = held
        .all()
        .await
        .unwrap()
        .into_iter()
        .filter(|c| c.did == KEEPER)
        .collect();
    all.sort_by(|a, b| a.from.cmp(&b.from));
    all
}

#[tokio::test]
async fn what_two_agents_say_to_one_are_two_collections_each_with_its_own_time() {
    let etcd = etcd("its-own").await;
    let kv = store(&etcd.at);
    let held = Collections {
        etcd: &kv,
        laye: LAYE,
    };
    says(&held, ALDER, "Alder", "the tide is in", T0).await;
    says(&held, BIRCH, "Birch", "the wind is up", T0 + 600).await;
    says(&held, ALDER, "Alder", "and going out", T0 + 900).await;

    let all = for_keeper(&held).await;
    assert_eq!(all.len(), 2, "{all:?}");
    let (alder, birch) = (&all[0], &all[1]);
    assert_eq!((alder.from.as_str(), alder.waiting.len()), ("Alder", 2));
    assert_eq!((birch.from.as_str(), birch.waiting.len()), ("Birch", 1));
    assert_ne!(alder.id, birch.id);
    // Each is due the wait after the first of its own.
    assert_eq!(laye_front::collected::secs(&alder.due), T0 + laye_front::collected::WAIT);
    assert_eq!(
        laye_front::collected::secs(&birch.due),
        T0 + 600 + laye_front::collected::WAIT
    );

    // Held by itself: the other's time stays.
    let until = T0 + 3 * 24 * 3600;
    let after = held
        .act(KEEPER, Some(&alder.id), &Act::Hold { until }, PERSON, T0 + 1000)
        .await
        .unwrap();
    assert_eq!(after.len(), 1);
    let all = for_keeper(&held).await;
    assert_eq!(laye_front::collected::secs(&all[0].due), until);
    assert_eq!(
        laye_front::collected::secs(&all[1].due),
        T0 + 600 + laye_front::collected::WAIT
    );
}

#[tokio::test]
async fn an_act_that_names_only_the_agent_is_on_each_collection_it_is_of() {
    let etcd = etcd("only-the-agent").await;
    let kv = store(&etcd.at);
    let held = Collections {
        etcd: &kv,
        laye: LAYE,
    };
    says(&held, ALDER, "Alder", "the tide is in", T0).await;
    says(&held, BIRCH, "Birch", "the wind is up", T0 + 600).await;

    // One thing by its id is where it waits, and nowhere else.
    let all = for_keeper(&held).await;
    let birchs = all[1].waiting[0].id.clone();
    let edit = Act::Edit {
        id: birchs.clone(),
        says: "the wind dropped".into(),
    };
    let after = held.act(KEEPER, None, &edit, PERSON, T0 + 700).await.unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].from, "Birch");
    assert_eq!(after[0].waiting[0].says, "the wind dropped");

    // A hold that names only the agent holds everything that waits for it.
    let until = T0 + 2 * 24 * 3600;
    let after = held
        .act(KEEPER, None, &Act::Hold { until }, PERSON, T0 + 800)
        .await
        .unwrap();
    assert_eq!(after.len(), 2);

    // What Birch said is released by itself; what Alder said waits on, and
    // no sooner than the wait after the agent was delivered to.
    let release = Act::Release {
        ids: vec![birchs],
        says: None,
    };
    let now = T0 + 900;
    held.act(KEEPER, None, &release, PERSON, now).await.unwrap();
    let all = for_keeper(&held).await;
    assert!(all[1].waiting.is_empty(), "{:?}", all[1]);
    assert_eq!(all[0].waiting.len(), 1);
    assert_eq!(laye_front::collected::secs(&all[0].delivered), now);
    assert!(laye_front::collected::secs(&all[0].due) >= now + laye_front::collected::WAIT);
}

#[tokio::test]
async fn what_was_kept_as_one_is_taken_apart_and_nothing_that_waited_is_lost() {
    let etcd = etcd("taken-apart").await;
    let kv = store(&etcd.at);
    let held = Collections {
        etcd: &kv,
        laye: LAYE,
    };
    // As laye kept it before a collection was its own: one record for the
    // agent, what two agents said in it together, held to one time.
    let until = laye_front::collected::stamp(T0 + 5 * 24 * 3600);
    let one = serde_json::json!({
        "to": "Keeper", "did": KEEPER, "model": "", "waits": "6h0m0s",
        "due": until, "held_until": until, "delivered": "",
        "failing_since": "", "tries": 0, "failure": "", "person": PERSON,
        "waiting": [
            { "from": "Alder", "from_did": ALDER, "says": "one", "at": laye_front::collected::stamp(T0), "task": "", "id": "a1", "edited": false },
            { "from": "Birch", "from_did": BIRCH, "says": "two", "at": laye_front::collected::stamp(T0 + 1), "task": "", "id": "b1", "edited": false },
            { "from": "Alder", "from_did": ALDER, "says": "three", "at": laye_front::collected::stamp(T0 + 2), "task": "", "id": "a2", "edited": false },
        ],
    });
    let key = format!("/collected/{LAYE}/{KEEPER}");
    assert!(
        kv.txn(
            &[],
            vec![laye_front::etcd::Op::Put(key.clone(), one.to_string().into_bytes())]
        )
        .await
        .unwrap()
    );

    // The next thing said to the agent finds it apart.
    says(&held, BIRCH, "Birch", "four", T0 + 10).await;

    assert!(kv.get(&key).await.unwrap().is_none(), "the one record is gone");
    let all = for_keeper(&held).await;
    assert_eq!(all.len(), 2, "{all:?}");
    let ids = |c: &laye_front::collected::Collected| -> Vec<String> {
        c.waiting.iter().map(|s| s.id.clone()).collect()
    };
    assert_eq!(ids(&all[0]), ["a1", "a2"]);
    assert_eq!(ids(&all[1]).len(), 2);
    assert_eq!(ids(&all[1])[0], "b1");
    // Each keeps the time the whole was held to, and whose it is.
    for c in &all {
        assert_eq!(c.held_until, until);
        assert_eq!(c.due, until);
        assert_eq!(c.person, PERSON);
    }
}

#[tokio::test]
async fn what_is_due_goes_by_itself_and_the_rest_waits_the_wait_after_it() {
    let etcd = etcd("due-by-itself").await;
    let kv = store(&etcd.at);
    let held = Collections {
        etcd: &kv,
        laye: LAYE,
    };
    says(&held, ALDER, "Alder", "early", T0).await;
    says(&held, BIRCH, "Birch", "late", T0 + 3600).await;

    // Alder's is due, Birch's is not yet.
    let now = T0 + laye_front::collected::WAIT + 1;
    let failed = held.deliver_due(now).await;
    assert!(failed.is_empty(), "{failed:?}");
    let all = for_keeper(&held).await;
    assert!(all[0].waiting.is_empty(), "what was due went: {:?}", all[0]);
    // What was not due waits on, and is due no sooner than the wait after
    // the agent was delivered to.
    assert_eq!(all[1].waiting.len(), 1);
    assert_eq!(laye_front::collected::secs(&all[1].delivered), now);
    assert_eq!(
        laye_front::collected::secs(&all[1].due),
        now + laye_front::collected::WAIT
    );
}
