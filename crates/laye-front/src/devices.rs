//! A key asks to be a person's, and the person says yes at laye, in their
//! passkey session: RFC 8628, as QNTX's device flow, with what it decided kept
//! in etcd, so every laye knows whose the key is.

// "AND LAYE OWNS IDENTITY"
// "BUT LAYE DOES NOT REALLY OWN USER, THE QNTX WAY"
//
// What laye records is the key and the person it speaks for. What that person
// may do as a User on a node stays the node's to say. A key that is a person's
// admits a session's key at laye (/auth/admit), as a key laye's settings name
// does.

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::etcd::{Etcd, Op};

/// Whose a key is: `/keys/<did>`.
pub const KEYS: &str = "/keys/";
/// A sign-in waiting, by its user code: `/devices/user/<CODE>`.
const BY_USER_CODE: &str = "/devices/user/";
/// The user code a device code asks after: `/devices/code/<sha256 of it>`.
const BY_DEVICE_CODE: &str = "/devices/code/";
/// How long a sign-in waits for its yes, as QNTX's (homewardTTL).
const WAITS: u64 = 600;
/// How long a key waits between asks (RFC 8628 §3.2 interval), as QNTX's.
const INTERVAL: u64 = 5;
/// RFC 8628 §6.1's base-20 set, as QNTX draws from.
const ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// A key, and the person it is.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Yes {
    pub person: String,
    pub level: String,
    /// What the key called itself when it asked.
    pub label: String,
    pub at: u64,
    /// The laye the person said yes at.
    pub by: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Waiting {
    label: String,
    did: String,
    user_code: String,
    until: u64,
    #[serde(default)]
    yes: Option<Yes>,
}

/// What laye answers: a status and its body.
pub type Answer = (u16, serde_json::Value);

fn refused(status: u16, error: &str, why: impl Into<String>) -> Answer {
    (
        status,
        json!({ "error": error, "error_description": why.into() }),
    )
}

fn hashed(device_code: &str) -> String {
    Sha256::digest(device_code.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn user_code() -> String {
    let letters: String = (0..8)
        .map(|_| {
            let at = usize::from(rand::random::<u8>()) % ALPHABET.len();
            char::from(ALPHABET.get(at).copied().unwrap_or(b'B'))
        })
        .collect();
    format!(
        "{}-{}",
        letters.get(..4).unwrap_or_default(),
        letters.get(4..).unwrap_or_default()
    )
}

/// A user code as a person types it: any case, the dash optional.
fn plain(code: &str) -> String {
    let letters: String = code
        .trim()
        .to_ascii_uppercase()
        .chars()
        .filter(|c| *c != '-')
        .collect();
    match (letters.get(..4), letters.get(4..)) {
        (Some(a), Some(b)) if letters.len() == 8 => format!("{a}-{b}"),
        _ => letters,
    }
}

pub struct Devices<'a> {
    pub etcd: &'a Etcd,
    /// Where the person says yes: laye's page, at its first passkey origin.
    pub approve_at: &'a str,
    /// This laye's did:key.
    pub laye: &'a str,
}

impl Devices<'_> {
    /// A key asks to be signed in, naming its did:key and what it is called.
    pub async fn ask(&self, did: &str, label: &str, now: u64) -> Answer {
        let label = label.trim();
        if label.is_empty() {
            return refused(
                400,
                "invalid_request",
                "label names the key asking, which the person reads before saying yes",
            );
        }
        if let Err(e) = laye_me::didkey::decode(did) {
            return refused(400, "invalid_request", format!("did is no did:key: {e}"));
        }
        let device_code: String = (0..32)
            .map(|_| format!("{:02x}", rand::random::<u8>()))
            .collect();
        let code = user_code();
        let waiting = Waiting {
            label: label.into(),
            did: did.into(),
            user_code: code.clone(),
            until: now + WAITS,
            yes: None,
        };
        let (Ok(record), Ok(pointer)) = (serde_json::to_vec(&waiting), serde_json::to_vec(&code))
        else {
            return refused(500, "server_error", "the sign-in was not written down");
        };
        let at_user = format!("{BY_USER_CODE}{code}");
        let at_code = format!("{BY_DEVICE_CODE}{}", hashed(&device_code));
        match self
            .etcd
            .txn(
                &[(&at_user, 0)],
                vec![Op::Put(at_user.clone(), record), Op::Put(at_code, pointer)],
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => return refused(503, "slow_down", "that user code is taken; ask again"),
            Err(why) => return refused(503, "server_error", why),
        }
        let approve = format!("{}/laye/me", self.approve_at.trim_end_matches('/'));
        (
            200,
            json!({
                "device_code": device_code,
                "user_code": code,
                "verification_uri": approve,
                "verification_uri_complete": format!("{approve}?user_code={code}"),
                "expires_in": WAITS,
                "interval": INTERVAL,
            }),
        )
    }

    async fn waiting(&self, user_code: &str, now: u64) -> Result<(Waiting, i64), Answer> {
        let at = format!("{BY_USER_CODE}{}", plain(user_code));
        let held = self
            .etcd
            .get(&at)
            .await
            .map_err(|why| refused(503, "server_error", why))?
            .ok_or_else(|| refused(404, "not_found", "no sign-in waits under this code"))?;
        let waiting: Waiting = serde_json::from_slice(&held.value)
            .map_err(|e| refused(500, "server_error", format!("{at} does not read: {e}")))?;
        if waiting.until <= now {
            return Err(refused(
                404,
                "expired_token",
                "this sign-in waited past its time",
            ));
        }
        Ok((waiting, held.mod_revision))
    }

    /// What a person is asked to say yes to: the key and what it calls itself.
    pub async fn shown(&self, user_code: &str, now: u64) -> Answer {
        match self.waiting(user_code, now).await {
            Ok((w, _)) => (
                200,
                json!({
                    "label": w.label, "did": w.did, "user_code": w.user_code,
                    "said": w.yes.is_some(),
                    "asked_at": w.until.saturating_sub(WAITS), "until": w.until,
                }),
            ),
            Err(answer) => answer,
        }
    }

    /// The person, in their passkey session, says yes: the key is theirs.
    pub async fn approve(&self, user_code: &str, person: &str, level: &str, now: u64) -> Answer {
        let (mut waiting, revision) = match self.waiting(user_code, now).await {
            Ok(w) => w,
            Err(answer) => return answer,
        };
        if waiting.yes.is_some() {
            return refused(409, "invalid_grant", "this sign-in was already said yes to");
        }
        let yes = Yes {
            person: person.into(),
            level: level.into(),
            label: format!("{} {}", waiting.label, waiting.user_code),
            at: now,
            by: self.laye.into(),
        };
        waiting.yes = Some(yes.clone());
        let at = format!("{BY_USER_CODE}{}", waiting.user_code);
        let key = format!("{KEYS}{}", waiting.did);
        let (Ok(record), Ok(kept)) = (serde_json::to_vec(&waiting), serde_json::to_vec(&yes))
        else {
            return refused(500, "server_error", "the yes was not written down");
        };
        match self
            .etcd
            .txn(
                &[(&at, revision)],
                vec![Op::Put(at.clone(), record), Op::Put(key, kept)],
            )
            .await
        {
            Ok(true) => (
                200,
                json!({ "did": waiting.did, "person": person, "label": yes.label }),
            ),
            Ok(false) => refused(
                409,
                "invalid_grant",
                "the sign-in changed while you said yes; look again",
            ),
            Err(why) => refused(503, "server_error", why),
        }
    }

    /// The key asks whether its yes came (RFC 8628 §3.4): waiting, over, or
    /// whose it now is, answered once.
    pub async fn token(&self, device_code: &str, now: u64) -> Answer {
        let at_code = format!("{BY_DEVICE_CODE}{}", hashed(device_code));
        let pointer = match self.etcd.get(&at_code).await {
            Ok(Some(held)) => held.value,
            Ok(None) => {
                return refused(
                    400,
                    "expired_token",
                    "no sign-in is held under this device code",
                );
            }
            Err(why) => return refused(503, "server_error", why),
        };
        let Ok(code) = serde_json::from_slice::<String>(&pointer) else {
            return refused(500, "server_error", format!("{at_code} does not read"));
        };
        let (waiting, _) = match self.waiting(&code, now).await {
            Ok(w) => w,
            Err((_, body)) => return (400, body),
        };
        let Some(yes) = waiting.yes else {
            return refused(
                400,
                "authorization_pending",
                format!("waiting for the person at {}/laye/me", self.approve_at),
            );
        };
        // Answered once: the sign-in goes, the key stays the person's.
        if let Err(why) = self
            .etcd
            .txn(
                &[],
                vec![
                    Op::Delete(at_code),
                    Op::Delete(format!("{BY_USER_CODE}{code}")),
                ],
            )
            .await
        {
            return refused(503, "server_error", why);
        }
        (
            200,
            json!({ "did": waiting.did, "person": yes.person, "level": yes.level, "label": yes.label }),
        )
    }
}

/// Whose a key is, when a person said yes to it at laye.
pub async fn whose(etcd: &Etcd, did: &str) -> Result<Option<Yes>, String> {
    match etcd.get(&format!("{KEYS}{did}")).await? {
        Some(held) => serde_json::from_slice(&held.value)
            .map(Some)
            .map_err(|e| format!("{KEYS}{did} does not read: {e}")),
        None => Ok(None),
    }
}
