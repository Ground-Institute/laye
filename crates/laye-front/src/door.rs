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

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The bindings a login proves: its signature over the challenge is its key's,
/// and each binding is about that key and made by a signer laye trusts.
pub fn vouched<'a>(login: &'a Login, signers: &[String]) -> Result<Vec<&'a SignedBinding>, String> {
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
    Ok(login
        .bindings
        .iter()
        .filter(|b| {
            b.claim.peer_pubkey == key
                && signers.contains(&hex(&b.signer_pubkey))
                && b.verify().is_ok()
        })
        .collect())
}

/// The root identity a login reaches: the key itself, or an account a trusted
/// signer bound to it. Else why not.
pub fn admitted_as(login: &Login, roots: &[String], signers: &[String]) -> Result<String, String> {
    let vouched = vouched(login, signers)?;
    if roots.contains(&login.did) {
        return Ok(login.did.clone());
    }
    vouched
        .iter()
        .find(|b| roots.contains(&b.claim.canonical_id))
        .map(|b| b.claim.canonical_id.clone())
        .ok_or_else(|| "nothing presented is one of laye's root identities".into())
}
