//! Who gets in: laye's own root identities, from laye.toml.

// "AND LAYE OWNS IDENTITY"
// "the root identities administer the laye or mycelia network, however we want to call it"

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use laye_me::SignedBinding;
use serde::Deserialize;

/// What a browser sends to log in with laye: its did:key, its signature over
/// the challenge, and the bindings it holds.
#[derive(Debug, Deserialize)]
pub struct Login {
    pub did: String,
    pub signature: String,
    pub challenge: String,
    #[serde(default)]
    pub bindings: Vec<SignedBinding>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The root identity a login reaches: the key itself, or an account a trusted
/// signer bound to it. Else why not.
pub fn admitted_as(login: &Login, roots: &[String], signers: &[String]) -> Result<String, String> {
    let key = laye_me::didkey::decode(&login.did)
        .map_err(|e| format!("{} is not a did:key: {e}", login.did))?;
    let public = libp2p_identity::ed25519::PublicKey::try_from_bytes(&key)
        .map_err(|e| format!("{} is not an ed25519 key: {e}", login.did))?;
    let signature = B64URL
        .decode(&login.signature)
        .map_err(|e| format!("the signature is not base64url: {e}"))?;
    if !public.verify(login.challenge.as_bytes(), &signature) {
        return Err(format!(
            "the signature is not {}'s over the challenge",
            login.did
        ));
    }
    if roots.contains(&login.did) {
        return Ok(login.did.clone());
    }
    for binding in &login.bindings {
        let about_this_key = binding.claim.peer_pubkey == key;
        let trusted = signers.contains(&hex(&binding.signer_pubkey));
        if about_this_key
            && trusted
            && binding.verify().is_ok()
            && roots.contains(&binding.claim.canonical_id)
        {
            return Ok(binding.claim.canonical_id.clone());
        }
    }
    Err("nothing presented is one of laye's root identities".into())
}
