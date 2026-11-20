#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "prove it with two native peers passing one message through a third."

// "I want a new node, on cloudflare, called C"

// 「[Opus 5.5] The third is C. Run with LAYE_C_DIAL set to C's dial address, as
// C's /health says it; without it there is no C to go through, and this test
// says so and passes nothing.」

use std::collections::HashSet;
use std::time::{Duration, Instant};

use laye_net::{Net, NetConfig, NetEvent, PeerId, Topic};

fn client(dial: &str, topic: &Topic) -> (Net, laye_me::Keypair) {
    let keypair = laye_me::fresh();
    let (net, drive) = laye_net::new(NetConfig {
        bootstrap_addrs: vec![dial.to_string()],
        listen_addrs: Vec::new(),
        keypair: keypair.clone(),
        topics: vec![topic.clone()],
        identify_protocol: laye_peer::IDENTIFY.into(),
    })
    .unwrap();
    tokio::spawn(drive);
    (net, keypair)
}

#[tokio::test(flavor = "multi_thread")]
async fn one_message_goes_from_one_peer_to_another_through_c() {
    let Ok(dial) = std::env::var("LAYE_C_DIAL") else {
        eprintln!("LAYE_C_DIAL is not set: no C to go through");
        return;
    };
    let c: PeerId = PeerId(dial.rsplit("/p2p/").next().unwrap().to_string());
    let topic = Topic("laye/through-a-peer".into());
    let deadline = Instant::now() + Duration::from_secs(60);

    let (sender, sender_key) = client(&dial, &topic);
    let (receiver, _) = client(&dial, &topic);
    let sender_did = laye_peer::did_of(&sender_key).unwrap();

    let mut connected: [HashSet<PeerId>; 2] = [HashSet::new(), HashSet::new()];
    let mut arrived = None;
    let said = b"one message, through C".to_vec();

    while arrived.is_none() {
        assert!(
            Instant::now() < deadline,
            "the message never arrived through C"
        );
        sender.publish(&topic, &said).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        for (i, net) in [&sender, &receiver].into_iter().enumerate() {
            for event in net.poll_events() {
                match event {
                    NetEvent::PeerUp { peer, .. } => {
                        connected[i].insert(peer);
                    }
                    NetEvent::Message {
                        from_did, bytes, ..
                    } if i == 1 => {
                        arrived = Some((from_did, bytes));
                    }
                    NetEvent::Error(e) => eprintln!("{}: {e}", ["sender", "receiver"][i]),
                    _ => {}
                }
            }
        }
    }

    let (from_did, bytes) = arrived.unwrap();
    assert_eq!(bytes, said);
    assert_eq!(from_did.as_deref(), Some(sender_did.as_str()));
    let c_only: HashSet<PeerId> = [c].into();
    assert_eq!(connected[0], c_only);
    assert_eq!(connected[1], c_only);
}
