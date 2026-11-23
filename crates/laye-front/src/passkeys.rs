//! A person's passkeys, held by laye: made on what admitted them, kept in etcd
//! with it, and a sign-in on one asks that again without QNTX.

// "AND LAYE OWNS IDENTITY"
// "QNTX can be the thing that holds stuff durably"
// "why would it not be able to be many ?"
//
// A passkey is made for one relying party, laye's: the origins that ask for it
// are many, each named in /.well-known/webauthn. The binding that admitted the
// person is kept beside the passkey, so a sign-in re-verifies it here: its
// signature, its signer still trusted, the account still a root or still let
// in. A person's session is laye's signature, made by a passkey and nothing
// else: no key opens one (ADR-060).

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ciborium::Value;
use laye_me::{Keypair, SignedBinding};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::etcd::{Etcd, Op};
use crate::jwt;

/// Where a passkey is kept, by its credential id in base64url: `/passkeys/<id>`.
pub const PASSKEYS: &str = "/passkeys/";
/// What a person is shown as: `/people/<person>`.
pub const PEOPLE: &str = "/people/";
/// How long a ceremony may take, as QNTX allows one (ceremonyTimeout).
const CEREMONY_LIFE: u64 = 300;
/// How long a person's session lasts.
pub const SESSION_LIFE: u64 = 3600;
/// The cookie a person's session is carried in.
pub const SESSION_COOKIE: &str = "laye_person";
/// Whom a person's session is for: laye, and no node.
const SESSION_AUD: &str = "laye person";
/// How often a sign-in's record is written again when another laye wrote between.
const TRIES: usize = 5;

/// COSE algorithms laye takes: EdDSA and ES256.
const EDDSA: i64 = -8;
const ES256: i64 = -7;

/// The flags an authenticator sets (WebAuthn §6.1).
const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
const ATTESTED: u8 = 0x40;

/// laye's relying party, and the origins that may ask for its passkeys.
#[derive(Clone, Debug, Deserialize)]
pub struct PasskeysAt {
    /// The relying party every passkey is made for: laye.ground.institute.
    pub rp_id: String,
    /// The origins a ceremony may come from: https://laye.ground.institute,
    /// https://l.sbvh.nl. Those beside the relying party's own are named in
    /// its /.well-known/webauthn.
    pub origins: Vec<String>,
}

/// One passkey, as etcd keeps it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Passkey {
    /// Who it speaks for: the root identity or the invited account.
    pub person: String,
    /// ROOT or USER, as QNTX's levels are.
    pub level: String,
    /// What reached the person, re-verified at each sign-in. None for a root
    /// that is a did:key, whose signature was the whole proof.
    #[serde(default)]
    pub binding: Option<SignedBinding>,
    /// The COSE algorithm the key signs with.
    pub alg: i64,
    /// The public key, base64: 32 bytes for EdDSA, 65 (SEC1) for ES256.
    pub public_key: String,
    pub sign_count: u32,
    /// The keys each device derives from the passkey (the PRF), the enrolling
    /// one first.
    pub owners: Vec<String>,
    pub rp_id: String,
    /// The laye that made it.
    pub by: String,
    pub at: u64,
}

/// What a person is shown as, as the provider showed them when they proved
/// their account (QNTX `/auth/binding/result`): their name, their picture,
/// and the account it came from.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Shown {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub picture: String,
    #[serde(default)]
    pub account: String,
}

enum Asked {
    /// A passkey made for this person.
    Enrol {
        person: String,
        level: &'static str,
        binding: Option<Box<SignedBinding>>,
        shown: Option<Box<Shown>>,
    },
    /// A passkey answering, whoever's it is.
    SignIn,
}

struct Ceremony {
    asked: Asked,
    until: u64,
}

pub struct Passkeys {
    pub etcd: Etcd,
    pub at: PasskeysAt,
    ceremonies: Mutex<HashMap<String, Ceremony>>,
}

/// What laye answers: a status and its body, and a session to set.
pub struct Answer {
    pub status: u16,
    pub body: serde_json::Value,
    pub session: Option<String>,
}

fn refused(status: u16, why: impl Into<String>) -> Answer {
    Answer {
        status,
        body: json!({ "error": why.into() }),
        session: None,
    }
}

/// What the first half proved: who, at which level, by which binding.
pub type FirstHalf = (String, &'static str, Option<SignedBinding>);

/// A response's base64url field, decoded.
fn field(v: &serde_json::Value, path: &[&str]) -> Result<Vec<u8>, String> {
    let mut at = v;
    for name in path {
        at = at
            .get(name)
            .ok_or_else(|| format!("the response carries no {}", path.join(".")))?;
    }
    let text = at
        .as_str()
        .ok_or_else(|| format!("{} is not a string", path.join(".")))?;
    B64URL
        .decode(text.trim_end_matches('='))
        .map_err(|e| format!("{} is not base64url: {e}", path.join(".")))
}

/// What a ceremony's client data says, held to what laye asked: the kind, a
/// challenge laye issued, an origin laye takes, not framed by another.
struct ClientData {
    challenge: String,
    hash: [u8; 32],
}

fn client_data(raw: &[u8], kind: &str, origins: &[String]) -> Result<ClientData, String> {
    #[derive(Deserialize)]
    struct Said {
        #[serde(rename = "type")]
        kind: String,
        challenge: String,
        origin: String,
        #[serde(default, rename = "crossOrigin")]
        cross_origin: bool,
    }
    let said: Said =
        serde_json::from_slice(raw).map_err(|e| format!("the client data does not read: {e}"))?;
    if said.kind != kind {
        return Err(format!("the client data is a {}, not a {kind}", said.kind));
    }
    if !origins.contains(&said.origin) {
        return Err(format!(
            "{} is not an origin laye's passkeys answer at",
            said.origin
        ));
    }
    if said.cross_origin {
        return Err("the passkey answered inside a frame of another origin".into());
    }
    Ok(ClientData {
        challenge: said.challenge,
        hash: Sha256::digest(raw).into(),
    })
}

/// The authenticator data's head: the relying party it is for, its flags,
/// its counter.
struct AuthData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    sign_count: u32,
    rest: &'a [u8],
}

fn auth_data(raw: &[u8]) -> Result<AuthData<'_>, String> {
    if raw.len() < 37 {
        return Err("the authenticator data is shorter than 37 bytes".into());
    }
    let (rp_id_hash, rest) = raw.split_at(32);
    let flags = rest.first().copied().unwrap_or_default();
    let count: [u8; 4] = rest
        .get(1..5)
        .and_then(|c| c.try_into().ok())
        .ok_or("the authenticator data has no counter")?;
    Ok(AuthData {
        rp_id_hash,
        flags,
        sign_count: u32::from_be_bytes(count),
        rest: rest.get(5..).unwrap_or_default(),
    })
}

fn int_of(v: &Value) -> Option<i128> {
    match v {
        Value::Integer(i) => Some(i128::from(*i)),
        _ => None,
    }
}

fn get(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| int_of(k) == Some(key))
        .map(|(_, v)| v)
}

fn bytes_at(map: &[(Value, Value)], key: i128) -> Result<Vec<u8>, String> {
    match get(map, key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(format!("the public key has no bytes at {key}")),
    }
}

/// A COSE key (RFC 9053) as laye keeps it: its algorithm and its bytes.
fn cose_key(raw: &[u8]) -> Result<(i64, Vec<u8>), String> {
    let key: Value =
        ciborium::from_reader(raw).map_err(|e| format!("the public key is not CBOR: {e}"))?;
    let Value::Map(map) = key else {
        return Err("the public key is not a COSE map".into());
    };
    let alg = get(&map, 3)
        .and_then(int_of)
        .and_then(|a| i64::try_from(a).ok())
        .ok_or("the public key names no algorithm")?;
    let kty = get(&map, 1).and_then(int_of);
    let crv = get(&map, -1).and_then(int_of);
    match (alg, kty, crv) {
        (EDDSA, Some(1), Some(6)) => {
            let x = bytes_at(&map, -2)?;
            if x.len() != 32 {
                return Err("an Ed25519 key is 32 bytes".into());
            }
            Ok((EDDSA, x))
        }
        (ES256, Some(2), Some(1)) => {
            let (x, y) = (bytes_at(&map, -2)?, bytes_at(&map, -3)?);
            if x.len() != 32 || y.len() != 32 {
                return Err("a P-256 coordinate is 32 bytes".into());
            }
            let mut sec1 = vec![0x04];
            sec1.extend(x);
            sec1.extend(y);
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|e| format!("the P-256 key is not on the curve: {e}"))?;
            Ok((ES256, sec1))
        }
        _ => Err(format!(
            "laye takes EdDSA on Ed25519 and ES256 on P-256, and this is {alg} (kty {kty:?}, crv {crv:?})"
        )),
    }
}

/// Whether `signature` is the key's over `message`.
fn verifies(alg: i64, key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match alg {
        EDDSA => libp2p_identity::ed25519::PublicKey::try_from_bytes(key)
            .is_ok_and(|k| k.verify(message, signature)),
        ES256 => {
            use p256::ecdsa::signature::Verifier;
            let (Ok(k), Ok(s)) = (
                p256::ecdsa::VerifyingKey::from_sec1_bytes(key),
                p256::ecdsa::Signature::from_der(signature),
            ) else {
                return false;
            };
            k.verify(message, &s).is_ok()
        }
        _ => false,
    }
}

/// The key a device derived from the passkey, proven by its signature over
/// the challenge as laye sent it (QNTX `verifiedOwnerDID`). None when the
/// browser offered none.
fn owner_of(body: &serde_json::Value, challenge: &str) -> Result<Option<String>, String> {
    let Some(did) = body
        .get("user_did")
        .and_then(|d| d.as_str())
        .filter(|d| !d.is_empty())
    else {
        return Ok(None);
    };
    let signature = field(body, &["user_did_signature"])?;
    let key = laye_me::didkey::decode(did).map_err(|e| format!("{did} is not a did:key: {e}"))?;
    let public = libp2p_identity::ed25519::PublicKey::try_from_bytes(&key)
        .map_err(|e| format!("{did} is not an ed25519 key: {e}"))?;
    if !public.verify(challenge.as_bytes(), &signature) {
        return Err(format!("the signature is not {did}'s over the challenge"));
    }
    Ok(Some(did.to_string()))
}

impl Passkeys {
    pub fn new(etcd: Etcd, at: PasskeysAt) -> Self {
        Passkeys {
            etcd,
            at,
            ceremonies: Mutex::new(HashMap::new()),
        }
    }

    /// The relying party's /.well-known/webauthn: every origin that may ask
    /// for its passkeys.
    pub fn related(&self) -> serde_json::Value {
        json!({ "origins": self.at.origins })
    }

    fn begin(&self, asked: Asked, now: u64) -> String {
        let challenge = B64URL.encode(rand::random::<[u8; 32]>());
        let mut held = self.ceremonies.lock().unwrap_or_else(|p| p.into_inner());
        held.retain(|_, c| c.until > now);
        held.insert(
            challenge.clone(),
            Ceremony {
                asked,
                until: now + CEREMONY_LIFE,
            },
        );
        challenge
    }

    /// The ceremony a challenge began, once.
    fn finish(&self, challenge: &str, now: u64) -> Option<Asked> {
        self.ceremonies
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(challenge)
            .filter(|c| c.until > now)
            .map(|c| c.asked)
    }

    /// A passkey made for who the first half proved: what the browser is asked.
    pub fn enrol_begin(&self, first: FirstHalf, shown: Option<Shown>, now: u64) -> Answer {
        let (person, level, binding) = first;
        let handle = B64URL.encode(Sha256::digest(person.as_bytes()));
        // What the device's passkey sheet calls it: the account and the name,
        // as the person knows them, not the identity laye keys them by.
        let account = shown
            .as_ref()
            .map(|s| s.account.clone())
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| person.clone());
        let called = shown
            .as_ref()
            .map(|s| s.name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| account.clone());
        let challenge = self.begin(
            Asked::Enrol {
                person: person.clone(),
                level,
                binding: binding.map(Box::new),
                shown: shown.map(Box::new),
            },
            now,
        );
        Answer {
            status: 200,
            body: json!({ "publicKey": {
                "rp": { "id": self.at.rp_id, "name": "laye" },
                "user": { "id": handle, "name": account, "displayName": called },
                "challenge": challenge,
                "pubKeyCredParams": [
                    { "type": "public-key", "alg": EDDSA },
                    { "type": "public-key", "alg": ES256 },
                ],
                "timeout": CEREMONY_LIFE * 1000,
                "attestation": "none",
                // As QNTX asks (server/auth/handlers.go): Firefox 156 below
                // macOS 26.4 sends an enrolment that does not ask for the
                // platform to its security-key stack.
                "authenticatorSelection": {
                    "authenticatorAttachment": "platform",
                    "residentKey": "discouraged",
                    "userVerification": "required",
                },
            }}),
            session: None,
        }
    }

    /// The passkey made, checked, and kept in etcd for the person the
    /// ceremony began for. Answered with their session.
    pub async fn enrol_finish(&self, body: &[u8], laye: &str, key: &Keypair, now: u64) -> Answer {
        let body: serde_json::Value = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return refused(400, format!("the response does not read: {e}")),
        };
        match self.made(&body, laye, now).await {
            Ok(kept) => session_for(&kept, laye, key, now, "enrolled"),
            Err((status, why)) => refused(status, why),
        }
    }

    async fn made(
        &self,
        body: &serde_json::Value,
        laye: &str,
        now: u64,
    ) -> Result<Passkey, (u16, String)> {
        let bad = |why: String| (400, why);
        let raw_client = field(body, &["response", "clientDataJSON"]).map_err(bad)?;
        let client = client_data(&raw_client, "webauthn.create", &self.at.origins).map_err(bad)?;
        let Some(Asked::Enrol {
            person,
            level,
            binding,
            shown,
        }) = self.finish(&client.challenge, now)
        else {
            return Err((401, "laye began no such enrolment, or it is over".into()));
        };
        let raw_attested = field(body, &["response", "attestationObject"]).map_err(bad)?;
        let attested: Value = ciborium::from_reader(raw_attested.as_slice())
            .map_err(|e| bad(format!("the attestation is not CBOR: {e}")))?;
        let Value::Map(attested) = attested else {
            return Err(bad("the attestation is not a map".into()));
        };
        let named = |name: &str| {
            attested.iter().find_map(|(k, v)| match k {
                Value::Text(k) if k == name => Some(v.clone()),
                _ => None,
            })
        };
        // laye asked for none, and a browser asked for none sends none: laye
        // trusts no maker's statement about an authenticator.
        if !matches!(named("fmt"), Some(Value::Text(f)) if f == "none") {
            return Err(bad(
                "laye asks for no attestation, and this carries one".into()
            ));
        }
        let Some(Value::Bytes(raw_auth)) = named("authData") else {
            return Err(bad("the attestation carries no authenticator data".into()));
        };
        let auth = auth_data(&raw_auth).map_err(bad)?;
        self.for_us(&auth).map_err(bad)?;
        if auth.flags & ATTESTED == 0 {
            return Err(bad("the authenticator data carries no credential".into()));
        }
        // The aaguid (16 bytes), then the credential id's length (2).
        let len = match auth.rest.get(16..18) {
            Some([hi, lo]) => usize::from(u16::from_be_bytes([*hi, *lo])),
            _ => return Err(bad("the credential has no length".into())),
        };
        let id = auth
            .rest
            .get(18..18 + len)
            .ok_or_else(|| bad("the credential id is cut short".into()))?;
        let cose = auth.rest.get(18 + len..).unwrap_or_default();
        let (alg, public_key) = cose_key(cose).map_err(bad)?;
        let raw_id = field(body, &["rawId"]).map_err(bad)?;
        if raw_id != id {
            return Err(bad("the credential id answered is not the one made".into()));
        }
        // A device that derives no key from the passkey is refused, as QNTX
        // refuses it (QNTX-Web passkey.ts):
        // "the passkey would belong to nobody"
        let owner = owner_of(body, &client.challenge)
            .map_err(bad)?
            .ok_or_else(|| {
                bad(
                    "this authenticator derived no key, so the passkey would belong to nobody"
                        .into(),
                )
            })?;
        let kept = Passkey {
            person,
            level: level.to_string(),
            binding: binding.map(|b| *b),
            alg,
            public_key: B64.encode(public_key),
            sign_count: auth.sign_count,
            owners: vec![owner],
            rp_id: self.at.rp_id.clone(),
            by: laye.to_string(),
            at: now,
        };
        let at = format!("{PASSKEYS}{}", B64URL.encode(id));
        let value = serde_json::to_vec(&kept).map_err(|e| (500, e.to_string()))?;
        let mut ops = vec![Op::Put(at.clone(), value)];
        if let Some(shown) = shown {
            let shown = serde_json::to_vec(&*shown).map_err(|e| (500, e.to_string()))?;
            ops.push(Op::Put(format!("{PEOPLE}{}", kept.person), shown));
        }
        match self.etcd.txn(&[(&at, 0)], ops).await {
            Ok(true) => Ok(kept),
            Ok(false) => Err((409, "laye already keeps this passkey".into())),
            Err(why) => Err((503, why)),
        }
    }

    fn for_us(&self, auth: &AuthData<'_>) -> Result<(), String> {
        let ours: [u8; 32] = Sha256::digest(self.at.rp_id.as_bytes()).into();
        if auth.rp_id_hash != ours {
            return Err(format!("the passkey is not {}'s", self.at.rp_id));
        }
        if auth.flags & USER_PRESENT == 0 || auth.flags & USER_VERIFIED == 0 {
            return Err("the authenticator did not verify the person".into());
        }
        Ok(())
    }

    /// A sign-in: the passkeys this browser made here, or, where it holds
    /// none, every passkey laye keeps. Each is named with the transports a
    /// platform passkey answers on: Firefox 156 below macOS 26.4 sends a
    /// sign-in whose allow list names neither internal nor hybrid to its
    /// security-key stack (QNTX credentials.go).
    pub async fn sign_in_begin(&self, body: &[u8], now: u64) -> Answer {
        #[derive(Deserialize, Default)]
        struct Named {
            #[serde(default)]
            ids: Vec<String>,
        }
        let asked: Named = serde_json::from_slice(body).unwrap_or_default();
        let ids = if asked.ids.is_empty() {
            match self.etcd.under(PASSKEYS).await {
                Ok(all) => all
                    .into_iter()
                    .filter_map(|(key, _)| key.strip_prefix(PASSKEYS).map(str::to_string))
                    .collect(),
                Err(why) => return refused(503, why),
            }
        } else {
            asked.ids
        };
        let allowed: Vec<serde_json::Value> = ids
            .iter()
            .filter(|id| B64URL.decode(id.as_bytes()).is_ok())
            .map(|id| json!({ "type": "public-key", "id": id, "transports": ["internal", "hybrid"] }))
            .collect();
        let challenge = self.begin(Asked::SignIn, now);
        Answer {
            status: 200,
            body: json!({ "publicKey": {
                "challenge": challenge,
                "rpId": self.at.rp_id,
                "timeout": CEREMONY_LIFE * 1000,
                "userVerification": "required",
                "allowCredentials": allowed,
            }}),
            session: None,
        }
    }

    /// The passkey answered, checked against what etcd keeps of it, and what
    /// admitted its person asked again. Answered with their session.
    pub async fn sign_in_finish(
        &self,
        body: &[u8],
        still: impl Fn(&Passkey) -> Result<(), String>,
        laye: &str,
        key: &Keypair,
        now: u64,
    ) -> Answer {
        let body: serde_json::Value = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return refused(400, format!("the response does not read: {e}")),
        };
        match self.answered(&body, still, now).await {
            Ok(kept) => session_for(&kept, laye, key, now, "asserted"),
            Err((status, why)) => refused(status, why),
        }
    }

    async fn answered(
        &self,
        body: &serde_json::Value,
        still: impl Fn(&Passkey) -> Result<(), String>,
        now: u64,
    ) -> Result<Passkey, (u16, String)> {
        let bad = |why: String| (400, why);
        let raw_client = field(body, &["response", "clientDataJSON"]).map_err(bad)?;
        let client = client_data(&raw_client, "webauthn.get", &self.at.origins).map_err(bad)?;
        if !matches!(self.finish(&client.challenge, now), Some(Asked::SignIn)) {
            return Err((401, "laye began no such sign-in, or it is over".into()));
        }
        let raw_auth = field(body, &["response", "authenticatorData"]).map_err(bad)?;
        let auth = auth_data(&raw_auth).map_err(bad)?;
        self.for_us(&auth).map_err(bad)?;
        let signature = field(body, &["response", "signature"]).map_err(bad)?;
        let at = format!(
            "{PASSKEYS}{}",
            B64URL.encode(field(body, &["rawId"]).map_err(bad)?)
        );
        let owner = owner_of(body, &client.challenge).map_err(bad)?;
        let mut signed = raw_auth.clone();
        signed.extend_from_slice(&client.hash);
        for _ in 0..TRIES {
            let Some(held) = self.etcd.get(&at).await.map_err(|why| (503, why))? else {
                return Err((401, "laye keeps no such passkey".into()));
            };
            let mut kept: Passkey = serde_json::from_slice(&held.value)
                .map_err(|e| (500, format!("the passkey kept at {at} does not read: {e}")))?;
            let public_key = B64
                .decode(&kept.public_key)
                .map_err(|e| (500, format!("the key kept at {at} is not base64: {e}")))?;
            if !verifies(kept.alg, &public_key, &signed, &signature) {
                return Err((401, "the signature is not this passkey's".into()));
            }
            // §7.2 step 22: a counter that did not advance is a sign it was copied.
            if (auth.sign_count != 0 || kept.sign_count != 0) && auth.sign_count <= kept.sign_count
            {
                return Err((
                    401,
                    "this passkey's counter did not advance, a sign it was copied".into(),
                ));
            }
            still(&kept).map_err(|why| (403, why))?;
            kept.sign_count = auth.sign_count;
            // The same passkey on one more device is recorded, not refused.
            if let Some(owner) = &owner
                && !kept.owners.contains(owner)
            {
                kept.owners.push(owner.clone());
            }
            let value = serde_json::to_vec(&kept).map_err(|e| (500, e.to_string()))?;
            match self
                .etcd
                .txn(
                    &[(&at, held.mod_revision)],
                    vec![Op::Put(at.clone(), value)],
                )
                .await
            {
                Ok(true) => return Ok(kept),
                Ok(false) => continue,
                Err(why) => return Err((503, why)),
            }
        }
        Err((503, format!("{at} kept changing under laye")))
    }
}

fn session_for(kept: &Passkey, laye: &str, key: &Keypair, now: u64, how: &str) -> Answer {
    match session(kept, laye, key, now) {
        Ok(token) => Answer {
            status: 200,
            body: json!({
                "person": kept.person,
                "level": kept.level,
                "passkey": how,
                "until": now + SESSION_LIFE,
            }),
            session: Some(token),
        },
        Err(why) => refused(500, format!("the session was not signed: {why}")),
    }
}

/// A person's session: laye's signature naming them, for laye, short-lived.
fn session(kept: &Passkey, laye: &str, key: &Keypair, now: u64) -> Result<String, String> {
    session_of(&kept.person, &kept.level, laye, key, now)
}

/// A session for person at level: what a passkey's yes gets, and what laye's
/// app gets for its key and the account it is bound to (lib.rs, APP_SESSION).
pub fn session_of(
    person: &str,
    level: &str,
    laye: &str,
    key: &Keypair,
    now: u64,
) -> Result<String, String> {
    jwt::sign(
        key,
        &jwt::Claims {
            iss: laye.to_string(),
            sub: person.to_string(),
            aud: vec![SESSION_AUD.into()],
            exp: now + SESSION_LIFE,
            iat: now,
            jti: jwt::fresh_jti(),
            label: level.to_string(),
        },
    )
    .map_err(|e| e.to_string())
}

/// What a person is shown as, when laye was told.
pub async fn shown_of(etcd: &Etcd, person: &str) -> Result<Option<Shown>, String> {
    match etcd.get(&format!("{PEOPLE}{person}")).await? {
        Some(kv) => serde_json::from_slice(&kv.value)
            .map(Some)
            .map_err(|e| format!("{PEOPLE}{person} does not read: {e}")),
        None => Ok(None),
    }
}

/// The person a session is, when it is this laye's and still lasts: who,
/// their level, and until when.
pub fn person_of(token: &str, laye: &str, now: u64) -> Result<(String, String, u64), String> {
    let claims = jwt::read(token).map_err(|e| format!("the session does not verify: {e}"))?;
    if claims.iss != laye {
        return Err(format!(
            "the session is {}'s, and this laye is {laye}",
            claims.iss
        ));
    }
    if !claims.aud.iter().any(|a| a == SESSION_AUD) {
        return Err("the token is no person's session".into());
    }
    if claims.exp <= now {
        return Err("the session is over".into());
    }
    Ok((claims.sub, claims.label, claims.exp))
}
