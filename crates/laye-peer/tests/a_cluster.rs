#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "before we have more ergonomic names, we should have the cluster be ready everywhere right?"

use std::time::{Duration, Instant};

use laye_net::{Net, NetEvent, PeerId, Topic};

/// Every event a peer said, kept, so what came before a wait is not lost.
#[derive(Default)]
struct Heard(Vec<NetEvent>);

impl Heard {
    fn take(&mut self, net: &Net) {
        self.0.extend(net.poll_events());
    }
    fn listening(&self) -> Option<String> {
        self.0.iter().find_map(|e| match e {
            NetEvent::Listening { addr } => Some(addr.clone()),
            _ => None,
        })
    }
    fn up(&self, peer: &PeerId) -> usize {
        self.0
            .iter()
            .filter(|e| matches!(e, NetEvent::PeerUp { peer: p, .. } if p == peer))
            .count()
    }
    fn down(&self, peer: &PeerId) -> bool {
        self.0
            .iter()
            .any(|e| matches!(e, NetEvent::PeerDown { peer: p, .. } if p == peer))
    }
    fn said(&self, bytes: &[u8]) -> bool {
        self.0
            .iter()
            .any(|e| matches!(e, NetEvent::Message { bytes: b, .. } if b == bytes))
    }
}

async fn until(deadline: Instant, what: &str, mut done: impl FnMut() -> bool) {
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A peer dialed by its node's name, which goes away and comes back with the
/// same key on the same port, is in the mesh again without anyone dialing it:
/// the peer that stays with it dials it again.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_comes_back_is_in_the_mesh_again() {
    let topic = Topic("laye/a-cluster".into());
    let deadline = Instant::now() + Duration::from_secs(60);

    let a_key = laye_me::fresh();
    let (a, drive) = laye_peer::listening(
        a_key.clone(),
        vec!["/ip4/127.0.0.1/tcp/0/ws".into()],
        Vec::new(),
        vec![topic.clone()],
    )
    .unwrap();
    let a_driving = tokio::spawn(drive);
    let mut a_heard = Heard::default();
    let mut at = None;
    until(deadline, "a never said where it listens", || {
        a_heard.take(&a);
        at = a_heard.listening();
        at.is_some()
    })
    .await;
    let at = at.unwrap();
    let port = at
        .split('/')
        .skip_while(|p| *p != "tcp")
        .nth(1)
        .unwrap()
        .to_string();
    let a_id = a.identity().clone();

    // By name, as q, k and l dial each other.
    let (b, drive) = laye_peer::listening(
        laye_me::fresh(),
        vec!["/ip4/127.0.0.1/tcp/0/ws".into()],
        vec![format!("/dns4/localhost/tcp/{port}/ws/p2p/{}", a_id.0)],
        vec![topic.clone()],
    )
    .unwrap();
    tokio::spawn(drive);
    let b_id = b.identity().clone();
    let mut b_heard = Heard::default();

    let first = b"before it went away".to_vec();
    until(deadline, "a's first word never reached b", || {
        a.publish(&topic, &first).unwrap();
        a_heard.take(&a);
        b_heard.take(&b);
        b_heard.said(&first)
    })
    .await;

    // a goes away: its swarm, and every connection it held, is dropped.
    a_driving.abort();
    drop(a);
    until(deadline, "b never saw a go", || {
        b_heard.take(&b);
        b_heard.down(&a_id)
    })
    .await;

    // a comes back as itself, dialing nobody.
    let (a, drive) = laye_peer::listening(
        a_key,
        vec![format!("/ip4/127.0.0.1/tcp/{port}/ws")],
        Vec::new(),
        vec![topic.clone()],
    )
    .unwrap();
    tokio::spawn(drive);
    assert_eq!(a.identity(), &a_id, "a came back as another peer");
    let mut a_heard = Heard::default();

    let second = b"after it came back".to_vec();
    until(
        deadline,
        "a's word after coming back never reached b",
        || {
            a.publish(&topic, &second).unwrap();
            a_heard.take(&a);
            b_heard.take(&b);
            b_heard.said(&second)
        },
    )
    .await;

    // b dialed a again: a, which dials nobody, was reached by b.
    assert_eq!(a_heard.up(&b_id), 1);
    assert_eq!(b_heard.up(&a_id), 2);
}
