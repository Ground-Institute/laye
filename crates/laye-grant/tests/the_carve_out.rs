#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use laye_grant::wire::{self, Narrow, Opens, State, Statement, Why, claim::Says, grant::To};
use laye_grant::{Answer, Keeper, Transcripts, did_of, digest, id_of, read, sign};
use laye_me::Keypair;

const GROUND: &str = "github.com/teranos/ground";
const NOW: u64 = 1_800_000_000;

/// Three rows of Robert's transcripts on ground.
struct Rows;

impl Transcripts for Rows {
    fn after(&self, _agent: &str, _repo: &str, after: u64) -> Vec<Vec<u8>> {
        let rows = [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()];
        rows.into_iter().skip(after as usize).collect()
    }
}

struct World {
    bob: Keypair,
    alice: Keypair,
    robert: Keypair,
    allister: Keypair,
    another: Keypair,
    eve_key: Keypair,
    eve: Keeper,
}

fn world() -> World {
    let eve_key = laye_me::fresh();
    World {
        bob: laye_me::fresh(),
        alice: laye_me::fresh(),
        robert: laye_me::fresh(),
        allister: laye_me::fresh(),
        another: laye_me::fresh(),
        eve: Keeper::new(eve_key.clone()).unwrap(),
        eve_key,
    }
}

fn did(key: &Keypair) -> String {
    did_of(key).unwrap()
}

/// Bob lets `to` read Robert, on ground.
fn grant(w: &World, to: To, narrow: Narrow, opens: Opens) -> Statement {
    sign(
        &w.bob,
        Says::Grant(wire::Grant {
            kind: wire::Kind::Read as i32,
            giver: did(&w.bob),
            named_agent: did(&w.robert),
            to: Some(to),
            repo: GROUND.into(),
            opens: opens as i32,
            keeper: did(&w.eve_key),
            narrow: narrow as i32,
            until: 0,
            issued_at: NOW,
        }),
    )
    .unwrap()
}

fn to_alice(w: &World) -> Statement {
    grant(
        w,
        To::Person(did(&w.alice)),
        Narrow::ToThatAgent,
        Opens::Transcripts,
    )
}

fn authorization(person: &Keypair, grant: &Statement, agent: &Keypair) -> Statement {
    sign(
        person,
        Says::Authorization(wire::Authorization {
            grant: id_of(grant).to_vec(),
            agent: did(agent),
            until: 0,
            issued_at: NOW,
        }),
    )
    .unwrap()
}

fn ask(
    agent: &Keypair,
    grant: &Statement,
    authorization: Option<&Statement>,
    at: u64,
) -> Statement {
    sign(
        agent,
        Says::Ask(wire::Ask {
            grant: id_of(grant).to_vec(),
            authorization: authorization.map(|h| id_of(h).to_vec()).unwrap_or_default(),
            reader: did(agent),
            after: 0,
            issued_at: at,
        }),
    )
    .unwrap()
}

fn revoke(signer: &Keypair, statement: &Statement) -> Statement {
    sign(
        signer,
        Says::Revoke(wire::Revoke {
            statement: id_of(statement).to_vec(),
            issued_at: NOW,
        }),
    )
    .unwrap()
}

fn why(answer: Answer) -> Why {
    let Answer::Refused(refused) = answer else {
        panic!("not refused: {answer:?}");
    };
    let Says::Refused(r) = read(&refused).unwrap().says else {
        panic!("not a Refused");
    };
    r.why()
}

fn stands(statement: &Statement) -> wire::Stands {
    let Says::Stands(s) = read(statement).unwrap().says else {
        panic!("not a Stands");
    };
    s
}

#[test]
fn alice_has_allister_read_robert() {
    let mut w = world();
    let g = to_alice(&w);
    w.eve.hold(&g).unwrap();
    let h = authorization(&w.alice, &g, &w.allister);
    let a = ask(&w.allister, &g, Some(&h), NOW);

    let Answer::Served {
        served,
        bodies,
        stands: narrowed,
    } = w.eve.ask(&a, None, Some(&h), &Rows, NOW).unwrap()
    else {
        panic!("not served");
    };

    assert_eq!(
        bodies,
        vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
    );
    let said = read(&served).unwrap();
    assert_eq!(said.signer, did(&w.eve_key));
    let Says::Served(s) = said.says else {
        panic!("not a Served");
    };
    assert_eq!(s.ask, id_of(&a).to_vec());
    assert_eq!((s.after, s.upto), (0, 3));
    assert_eq!(s.digest, digest(&bodies).to_vec());

    // Bob never named Allister. The grant is Allister's now, and says so.
    let narrowed = stands(&narrowed.unwrap());
    assert_eq!(narrowed.state(), State::Narrowed);
    assert_eq!(narrowed.agent, did(&w.allister));
    assert_eq!(narrowed.served, id_of(&served).to_vec());
}

#[test]
fn an_agent_alice_did_not_authorize_is_refused() {
    let mut w = world();
    let g = to_alice(&w);
    w.eve.hold(&g).unwrap();

    let bare = ask(&w.another, &g, None, NOW);
    let answer = w.eve.ask(&bare, None, None, &Rows, NOW).unwrap();
    assert_eq!(why(answer), Why::NotAuthorized);

    // An authorization it wrote itself is not Alice's.
    let own = authorization(&w.another, &g, &w.another);
    let with_own = ask(&w.another, &g, Some(&own), NOW);
    let answer = w.eve.ask(&with_own, None, Some(&own), &Rows, NOW).unwrap();
    assert_eq!(why(answer), Why::NotAuthorized);

    // Allister's authorization, in another agent's Ask.
    let h = authorization(&w.alice, &g, &w.allister);
    let borrowed = ask(&w.another, &g, Some(&h), NOW);
    let answer = w.eve.ask(&borrowed, None, Some(&h), &Rows, NOW).unwrap();
    assert_eq!(why(answer), Why::NotTheAgent);
}

#[test]
fn once_allister_has_read_no_other_agent_of_alice_may() {
    let mut w = world();
    let g = to_alice(&w);
    w.eve.hold(&g).unwrap();
    let h = authorization(&w.alice, &g, &w.allister);
    let a = ask(&w.allister, &g, Some(&h), NOW);
    w.eve.ask(&a, None, Some(&h), &Rows, NOW).unwrap();

    let h2 = authorization(&w.alice, &g, &w.another);
    let a2 = ask(&w.another, &g, Some(&h2), NOW);
    let answer = w.eve.ask(&a2, None, Some(&h2), &Rows, NOW).unwrap();
    assert_eq!(why(answer), Why::NarrowedToAnother);

    // Allister still may.
    let again = ask(&w.allister, &g, Some(&h), NOW + 1);
    let answer = w.eve.ask(&again, None, Some(&h), &Rows, NOW + 1).unwrap();
    assert!(matches!(answer, Answer::Served { stands: None, .. }));
}

#[test]
fn when_not_narrowed_every_agent_alice_authorizes_may() {
    let mut w = world();
    let g = grant(
        &w,
        To::Person(did(&w.alice)),
        Narrow::NotNarrowed,
        Opens::Transcripts,
    );
    let id = w.eve.hold(&g).unwrap();
    for agent in [&w.allister, &w.another] {
        let h = authorization(&w.alice, &g, agent);
        let a = ask(agent, &g, Some(&h), NOW);
        let answer = w.eve.ask(&a, None, Some(&h), &Rows, NOW).unwrap();
        assert!(matches!(answer, Answer::Served { stands: None, .. }));
    }
    assert_eq!(w.eve.state(&id), Some(State::Given));
}

#[test]
fn bob_can_revoke_it() {
    let mut w = world();
    let g = to_alice(&w);
    let id = w.eve.hold(&g).unwrap();
    let h = authorization(&w.alice, &g, &w.allister);

    // Alice cannot revoke Bob's grant.
    assert!(w.eve.revoke(&revoke(&w.alice, &g), NOW).is_err());
    assert_eq!(w.eve.state(&id), Some(State::Given));

    let said = w.eve.revoke(&revoke(&w.bob, &g), NOW).unwrap().unwrap();
    assert_eq!(stands(&said).state(), State::Revoked);

    let a = ask(&w.allister, &g, Some(&h), NOW);
    let answer = w.eve.ask(&a, None, Some(&h), &Rows, NOW).unwrap();
    assert_eq!(why(answer), Why::RevokedGrant);
}

#[test]
fn alice_takes_it_back_from_allister_and_it_is_spent() {
    let mut w = world();
    let g = to_alice(&w);
    w.eve.hold(&g).unwrap();
    let h = authorization(&w.alice, &g, &w.allister);
    let a = ask(&w.allister, &g, Some(&h), NOW);
    w.eve.ask(&a, None, Some(&h), &Rows, NOW).unwrap();

    let said = w.eve.revoke(&revoke(&w.alice, &h), NOW).unwrap().unwrap();
    let spent = stands(&said);
    assert_eq!(spent.state(), State::Spent);
    assert_eq!(spent.agent, did(&w.allister));

    let again = ask(&w.allister, &g, Some(&h), NOW + 1);
    let answer = w.eve.ask(&again, None, Some(&h), &Rows, NOW + 1).unwrap();
    assert_eq!(why(answer), Why::SpentGrant);

    // No other authorization revives it.
    let h2 = authorization(&w.alice, &g, &w.another);
    let a2 = ask(&w.another, &g, Some(&h2), NOW + 1);
    let answer = w.eve.ask(&a2, None, Some(&h2), &Rows, NOW + 1).unwrap();
    assert_eq!(why(answer), Why::SpentGrant);
}

#[test]
fn a_grant_to_one_agent_needs_no_authorization_and_serves_no_other() {
    let mut w = world();
    let g = grant(
        &w,
        To::Agent(did(&w.allister)),
        Narrow::ToThatAgent,
        Opens::Transcripts,
    );
    let id = w.eve.hold(&g).unwrap();

    let a = ask(&w.allister, &g, None, NOW);
    let answer = w.eve.ask(&a, None, None, &Rows, NOW).unwrap();
    assert!(matches!(answer, Answer::Served { stands: None, .. }));
    assert_eq!(w.eve.state(&id), Some(State::Given));

    let other = ask(&w.another, &g, None, NOW);
    let answer = w.eve.ask(&other, None, None, &Rows, NOW).unwrap();
    assert_eq!(why(answer), Why::NotTheAgent);
}

#[test]
fn checks_open_none_of_the_transcripts() {
    let mut w = world();
    let g = grant(
        &w,
        To::Agent(did(&w.allister)),
        Narrow::ToThatAgent,
        Opens::Checks,
    );
    w.eve.hold(&g).unwrap();
    let a = ask(&w.allister, &g, None, NOW);
    let Answer::Served { bodies, .. } = w.eve.ask(&a, None, None, &Rows, NOW).unwrap() else {
        panic!("not served");
    };
    assert!(bodies.is_empty());
}

#[test]
fn a_grant_that_does_not_say_what_it_opens_opens_nothing() {
    let mut w = world();
    let g = grant(
        &w,
        To::Agent(did(&w.allister)),
        Narrow::ToThatAgent,
        Opens::Unspecified,
    );
    w.eve.hold(&g).unwrap();
    let a = ask(&w.allister, &g, None, NOW);
    let answer = w.eve.ask(&a, None, None, &Rows, NOW).unwrap();
    assert_eq!(why(answer), Why::OpensNothing);
}

#[test]
fn an_ask_is_answered_once_and_in_time() {
    let mut w = world();
    let g = grant(
        &w,
        To::Agent(did(&w.allister)),
        Narrow::ToThatAgent,
        Opens::Transcripts,
    );
    w.eve.hold(&g).unwrap();

    let a = ask(&w.allister, &g, None, NOW);
    w.eve.ask(&a, None, None, &Rows, NOW).unwrap();
    let answer = w.eve.ask(&a, None, None, &Rows, NOW).unwrap();
    assert_eq!(why(answer), Why::SeenBefore);

    let old = ask(&w.allister, &g, None, NOW - 301);
    let answer = w.eve.ask(&old, None, None, &Rows, NOW).unwrap();
    assert_eq!(why(answer), Why::OutOfTime);
}

#[test]
fn what_does_not_verify_gets_no_answer() {
    let mut w = world();
    let g = grant(
        &w,
        To::Agent(did(&w.allister)),
        Narrow::ToThatAgent,
        Opens::Transcripts,
    );
    w.eve.hold(&g).unwrap();

    // Another agent's Ask, under Allister's name.
    let mut forged = ask(&w.another, &g, None, NOW);
    forged.signer = did(&w.allister);
    let answer = w.eve.ask(&forged, None, None, &Rows, NOW).unwrap();
    assert!(matches!(answer, Answer::Silent));

    // A grant Bob did not sign is not held.
    let mut not_bobs = g.clone();
    not_bobs.signer = did(&w.alice);
    assert!(w.eve.hold(&not_bobs).is_err());
}

#[test]
fn a_grant_that_names_another_keeper_is_said_to() {
    let mut w = world();
    let mut other = Keeper::new(laye_me::fresh()).unwrap();
    let g = grant(
        &w,
        To::Agent(did(&w.allister)),
        Narrow::ToThatAgent,
        Opens::Transcripts,
    );
    let a = ask(&w.allister, &g, None, NOW);

    let answer = other.ask(&a, Some(&g), None, &Rows, NOW).unwrap();
    assert_eq!(why(answer), Why::NotThisKeeper);

    // Its own keeper takes it as it comes with the Ask.
    let answer = w.eve.ask(&a, Some(&g), None, &Rows, NOW).unwrap();
    assert!(matches!(answer, Answer::Served { .. }));
}
