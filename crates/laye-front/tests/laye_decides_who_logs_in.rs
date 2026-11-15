#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "AND LAYE OWNS IDENTITY"
// "the root identities administer the laye or mycelia network, however we want to call it"

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use laye_front::door::{Login, admitted_as};
use laye_me::{BindingClaim, SignedBinding};

const CHALLENGE: &str = "a-challenge-the-node-issued";

fn did(key: &laye_me::Keypair) -> String {
    laye_peer::did_of(key).unwrap()
}

fn public(key: &laye_me::Keypair) -> [u8; 32] {
    key.public().try_into_ed25519().unwrap().to_bytes()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn login(key: &laye_me::Keypair, bindings: Vec<SignedBinding>) -> Login {
    Login {
        did: did(key),
        signature: B64URL.encode(key.sign(CHALLENGE.as_bytes()).unwrap()),
        challenge: CHALLENGE.into(),
        bindings,
    }
}

fn binding(signer: &laye_me::Keypair, about: &laye_me::Keypair, account: &str) -> SignedBinding {
    let claim = BindingClaim {
        peer_pubkey: public(about),
        provider: "github".into(),
        canonical_id: account.into(),
        handle: None,
        issued_at: 1_794_000_000,
    };
    SignedBinding {
        signature: signer.sign(&claim.canonical_bytes()).unwrap(),
        signer_pubkey: public(signer),
        claim,
    }
}

#[test]
fn a_root_key_logs_in_as_itself() {
    let root = laye_me::fresh();
    let got = admitted_as(&login(&root, Vec::new()), &[did(&root)], &[]);
    assert_eq!(got, Ok(did(&root)));
}

#[test]
fn a_root_account_logs_in_through_a_binding_a_trusted_signer_made() {
    let device = laye_me::fresh();
    let signer = laye_me::fresh();
    let presented = login(&device, vec![binding(&signer, &device, "github:1739143")]);
    let got = admitted_as(
        &presented,
        &["github:1739143".into()],
        &[hex(&public(&signer))],
    );
    assert_eq!(got, Ok("github:1739143".to_string()));
}

#[test]
fn nobody_else_logs_in() {
    let stranger = laye_me::fresh();
    let root = laye_me::fresh();
    assert!(admitted_as(&login(&stranger, Vec::new()), &[did(&root)], &[]).is_err());
}

#[test]
fn a_binding_by_a_signer_laye_does_not_trust_admits_nobody() {
    let device = laye_me::fresh();
    let untrusted = laye_me::fresh();
    let presented = login(
        &device,
        vec![binding(&untrusted, &device, "github:1739143")],
    );
    assert!(admitted_as(&presented, &["github:1739143".into()], &[]).is_err());
}

#[test]
fn a_binding_about_another_key_admits_nobody() {
    let device = laye_me::fresh();
    let other = laye_me::fresh();
    let signer = laye_me::fresh();
    let presented = login(&device, vec![binding(&signer, &other, "github:1739143")]);
    assert!(
        admitted_as(
            &presented,
            &["github:1739143".into()],
            &[hex(&public(&signer))]
        )
        .is_err()
    );
}

#[test]
fn a_signature_over_another_challenge_admits_nobody() {
    let root = laye_me::fresh();
    let mut presented = login(&root, Vec::new());
    presented.challenge = "another-challenge".into();
    assert!(admitted_as(&presented, &[did(&root)], &[]).is_err());
}
