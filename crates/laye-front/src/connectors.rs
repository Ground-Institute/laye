//! The connectors' authorization server: claude.ai and ChatGPT send a person
//! to laye's screen, and are handed a token and a refresh token laye keeps in
//! the etcd q, k and l share. A refresh is one transaction: the next token is
//! written and the one presented is spent together, or neither is. QNTX asks
//! laye who a token is (QNTX server/auth/issuer.go).

// "BUT I WANT LAYE TO OWN IT, LAYE IS SUPPOSED TO FALL DOWN LESS EASILY THAN QNTX"

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::etcd::{Etcd, Op};
use crate::issuer::{self, Laye, Said, form, hash, json, random_hex, refused};

/// A connector, by its client id: its did:key.
pub const CLIENTS: &str = "/oauth/clients/";
const CODES: &str = "/oauth/codes/";
const TOKENS: &str = "/oauth/tokens/";
const REFRESH: &str = "/oauth/refresh/";

const CODE_LIFE: u64 = 120;
const TOKEN_LIFE: u64 = 3600;
/// A yes lasts thirty days of silence, as it did at QNTX: every refresh is
/// handed a new thirty days.
const REFRESH_LIFE: u64 = 30 * 24 * 3600;
/// How far the refresh tokens issued after a stolen one are followed.
const CHAIN: usize = 64;

/// A connector laye issues for: where its codes go, what of its secret is
/// kept, and the node its tokens are for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub did: String,
    pub label: String,
    /// Its one return address.
    pub back: String,
    /// The secret's sha256 in hex, the form QNTX kept it in.
    pub secret: String,
    /// ROOT's client is sent a code for ROOT and nobody else (QNTX ADR-038).
    #[serde(default)]
    pub root: bool,
    #[serde(default)]
    pub namespaces: Vec<String>,
    /// The node its tokens are for, by its did:key: the one laye answers
    /// about them.
    pub node: String,
    /// That node's public origin, the resource a request may name.
    pub resource: String,
}

#[derive(Serialize, Deserialize)]
struct Code {
    client: String,
    back: String,
    challenge: String,
    person: String,
    level: String,
    until: u64,
}

#[derive(Serialize, Deserialize)]
struct Access {
    client: String,
    person: String,
    level: String,
    /// The did:key the token's seed names, as QNTX names its own tokens.
    did: String,
    until: u64,
}

#[derive(Serialize, Deserialize)]
struct Refresh {
    client: String,
    person: String,
    level: String,
    until: u64,
    /// The access token issued with it, by hash.
    access: String,
    /// When it was spent.
    #[serde(default)]
    spent: Option<u64>,
    /// The refresh token it was spent for, by hash.
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize)]
struct Until {
    until: u64,
}

/// What laye answers a token request with, or that the refresh token is not
/// one laye issued: it is QNTX's, issued before laye issued for connectors.
pub enum Answered {
    Said(Said),
    NotLayes,
}

/// The connector a client id names, when laye issues for it.
pub async fn client(etcd: &Etcd, did: &str) -> Result<Option<Client>, String> {
    if did.is_empty() {
        return Ok(None);
    }
    let key = format!("{CLIENTS}{did}");
    match etcd.get(&key).await? {
        Some(kv) => serde_json::from_slice(&kv.value)
            .map(Some)
            .map_err(|e| format!("the client kept at {key} does not read: {e}")),
        None => Ok(None),
    }
}

/// The client id and secret a token request presents: as Basic
/// (RFC 6749 §2.3.1, each form-encoded), or in the form.
pub fn presented(authorization: Option<&str>, asked: &HashMap<String, String>) -> (String, String) {
    if let Some(basic) = authorization.and_then(|a| a.strip_prefix("Basic "))
        && let Ok(decoded) = B64.decode(basic.trim())
        && let Ok(pair) = String::from_utf8(decoded)
        && let Some((id, secret)) = pair.split_once(':')
    {
        return (issuer::decode(id), issuer::decode(secret));
    }
    let field = |name: &str| asked.get(name).cloned().unwrap_or_default();
    (field("client_id"), field("client_secret"))
}

/// scheme://host, without case.
fn origin(uri: &str) -> Option<String> {
    let (scheme, rest) = uri.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    Some(format!("{scheme}://{host}").to_lowercase())
}

/// Whether the resource a request names, if it names one, is the client's
/// node (RFC 8707).
fn for_its_node(client: &Client, asked: &HashMap<String, String>) -> Result<(), String> {
    let Some(named) = asked.get("resource") else {
        return Ok(());
    };
    if origin(named).is_some() && origin(named) == origin(&client.resource) {
        Ok(())
    } else {
        Err(format!(
            "{}'s tokens are for {}, not {named}",
            client.label, client.resource
        ))
    }
}

/// laye's screen, for a connector sending somebody to sign in.
pub fn authorize(laye: &Laye<'_>, client: &Client, query: &str) -> Said {
    let asked = form(query);
    if asked.get("redirect_uri") != Some(&client.back) {
        return refused(
            400,
            "invalid_request",
            format!(
                "{} is sent back to {}, and nowhere else",
                client.label, client.back
            ),
        );
    }
    if asked.get("response_type").map(String::as_str) != Some("code") {
        return refused(400, "unsupported_response_type", "laye answers with a code");
    }
    let s256 = asked.get("code_challenge_method").map(String::as_str) == Some("S256");
    let has_challenge = asked.get("code_challenge").is_some_and(|c| !c.is_empty());
    if !s256 || !has_challenge {
        return refused(400, "invalid_request", "laye takes a code challenge, S256");
    }
    if let Err(why) = for_its_node(client, &asked) {
        return refused(400, "invalid_target", why);
    }
    laye.page(Some(query))
}

/// A sign-in on laye's screen for a connector: who it proves, and the code
/// the connector is sent back with.
pub async fn login(
    laye: &Laye<'_>,
    etcd: &Etcd,
    client: &Client,
    journey: &str,
    body: &[u8],
) -> Said {
    let (_, person, level) = match laye.proven(body) {
        Ok(proven) => proven,
        Err(refusal) => return refusal,
    };
    let asked = form(journey);
    if asked.get("redirect_uri") != Some(&client.back) {
        return refused(
            400,
            "invalid_request",
            format!(
                "{} is sent back to {}, and nowhere else",
                client.label, client.back
            ),
        );
    }
    if client.root && level != issuer::ROOT {
        return refused(
            403,
            "access_denied",
            format!(
                "{} is ROOT's client, and {person} is not ROOT",
                client.label
            ),
        );
    }
    let code = random_hex(32);
    let held = Code {
        client: client.did.clone(),
        back: client.back.clone(),
        challenge: asked.get("code_challenge").cloned().unwrap_or_default(),
        person: person.clone(),
        level: level.to_string(),
        until: laye.now + CODE_LIFE,
    };
    let Ok(value) = serde_json::to_vec(&held) else {
        return refused(500, "server_error", "the code was not written");
    };
    match etcd
        .txn(&[], vec![Op::Put(format!("{CODES}{}", hash(&code)), value)])
        .await
    {
        Ok(true) => {}
        Ok(false) => return refused(500, "server_error", "etcd did not keep the code"),
        Err(why) => return refused(503, "temporarily_unavailable", why),
    }
    eprintln!(
        "laye-front: {person} signed in at laye for {} ({}), and it is sent a code",
        client.label, client.did
    );
    let state = asked.get("state").cloned().unwrap_or_default();
    let joined = if client.back.contains('?') { '&' } else { '?' };
    json(
        200,
        serde_json::json!({
            "redirect": format!(
                "{}{joined}code={}&state={}",
                client.back,
                issuer::encode(&code),
                issuer::encode(&state)
            ),
        }),
    )
}

/// A connector coming for its token, with its secret.
pub async fn token(
    laye: &Laye<'_>,
    etcd: &Etcd,
    client: &Client,
    secret: &str,
    asked: &HashMap<String, String>,
) -> Answered {
    if secret.is_empty() || hash(secret) != client.secret {
        return Answered::Said(refused(
            401,
            "invalid_client",
            format!("the secret presented is not {}'s", client.label),
        ));
    }
    if let Err(why) = for_its_node(client, asked) {
        return Answered::Said(refused(400, "invalid_target", why));
    }
    match asked.get("grant_type").map(String::as_str) {
        Some("authorization_code") => Answered::Said(by_code(laye, etcd, client, asked).await),
        Some("refresh_token") => by_refresh(laye, etcd, client, asked).await,
        _ => Answered::Said(refused(
            400,
            "unsupported_grant_type",
            "laye issues a connector a token for a code or a refresh token",
        )),
    }
}

async fn by_code(
    laye: &Laye<'_>,
    etcd: &Etcd,
    client: &Client,
    asked: &HashMap<String, String>,
) -> Said {
    let code = asked.get("code").map(String::as_str).unwrap_or_default();
    let key = format!("{CODES}{}", hash(code));
    let kv = match etcd.get(&key).await {
        Ok(Some(kv)) => kv,
        Ok(None) => {
            return refused(
                400,
                "invalid_grant",
                "laye issued no such code, or it is spent",
            );
        }
        Err(why) => return refused(503, "temporarily_unavailable", why),
    };
    let Ok(held) = serde_json::from_slice::<Code>(&kv.value) else {
        return refused(
            500,
            "server_error",
            format!("the code kept at {key} does not read"),
        );
    };
    let verifier = asked
        .get("code_verifier")
        .map(String::as_str)
        .unwrap_or_default();
    let verified = B64URL.encode(Sha256::digest(verifier.as_bytes())) == held.challenge;
    if held.until <= laye.now
        || held.client != client.did
        || asked.get("redirect_uri") != Some(&held.back)
        || !verified
    {
        return refused(
            400,
            "invalid_grant",
            "the code is not this client's, not for here, or the verifier is not its",
        );
    }
    let (answer, mut ops, _) = issue(laye.now, client, &held.person, &held.level);
    ops.push(Op::Delete(key.clone()));
    match etcd.txn(&[(&key, kv.mod_revision)], ops).await {
        Ok(true) => {
            eprintln!(
                "laye-front: a code was exchanged for a token, client={} person={}",
                client.did, held.person
            );
            json(200, answer)
        }
        Ok(false) => refused(
            400,
            "invalid_grant",
            "the code was spent at the same moment",
        ),
        Err(why) => refused(503, "temporarily_unavailable", why),
    }
}

// "A rotation is one etcd transaction: the new refresh token is written and the
// old one revoked together, or neither happens."
async fn by_refresh(
    laye: &Laye<'_>,
    etcd: &Etcd,
    client: &Client,
    asked: &HashMap<String, String>,
) -> Answered {
    let presented = asked
        .get("refresh_token")
        .map(String::as_str)
        .unwrap_or_default();
    let key = format!("{REFRESH}{}", hash(presented));
    let kv = match etcd.get(&key).await {
        Ok(Some(kv)) => kv,
        Ok(None) => return Answered::NotLayes,
        Err(why) => return Answered::Said(refused(503, "temporarily_unavailable", why)),
    };
    let Ok(mut held) = serde_json::from_slice::<Refresh>(&kv.value) else {
        return Answered::Said(refused(
            500,
            "server_error",
            format!("the refresh token kept at {key} does not read"),
        ));
    };
    if held.client != client.did {
        return Answered::Said(refused(
            400,
            "invalid_grant",
            format!("the refresh token is not {}'s", client.label),
        ));
    }
    // "A refresh token presented twice is still treated as stolen, as qq does now."
    if held.spent.is_some() {
        let revoked = revoke_after(etcd, held.next.clone(), laye.now).await;
        eprintln!(
            "laye-front: a spent refresh token was presented again, client={} person={}; {revoked} issued after it revoked",
            client.did, held.person
        );
        return Answered::Said(refused(
            400,
            "invalid_grant",
            "the refresh token was already spent, and what it was spent for is revoked",
        ));
    }
    if held.until <= laye.now {
        return Answered::Said(refused(400, "invalid_grant", "the refresh token has ended"));
    }
    if !laye.still_as(&held.person, &held.level) {
        return Answered::Said(refused(
            400,
            "invalid_grant",
            format!(
                "{} is no longer a root, or let in by an invitation",
                held.person
            ),
        ));
    }
    let (answer, mut ops, next) = issue(laye.now, client, &held.person, &held.level);
    held.spent = Some(laye.now);
    held.next = Some(next);
    let Ok(value) = serde_json::to_vec(&held) else {
        return Answered::Said(refused(
            500,
            "server_error",
            "the spent refresh token was not written",
        ));
    };
    ops.push(Op::Put(key.clone(), value));
    match etcd.txn(&[(&key, kv.mod_revision)], ops).await {
        Ok(true) => {
            eprintln!(
                "laye-front: a refresh token was exchanged for the next, client={} person={}",
                client.did, held.person
            );
            Answered::Said(json(200, answer))
        }
        Ok(false) => Answered::Said(refused(
            400,
            "invalid_grant",
            "the refresh token was spent at the same moment",
        )),
        Err(why) => Answered::Said(refused(503, "temporarily_unavailable", why)),
    }
}

/// A token and a refresh token for the person, and the writes that keep them:
/// what the connector is answered, the writes, and the refresh token's hash.
fn issue(
    now: u64,
    client: &Client,
    person: &str,
    level: &str,
) -> (serde_json::Value, Vec<Op>, String) {
    let seed: [u8; 32] = rand::random();
    let token = format!(
        "{}{}",
        issuer::TOKEN_PREFIX,
        seed.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let refresh = random_hex(32);
    let access = Access {
        client: client.did.clone(),
        person: person.to_string(),
        level: level.to_string(),
        did: did_of_seed(seed),
        until: now + TOKEN_LIFE,
    };
    let renewed = Refresh {
        client: client.did.clone(),
        person: person.to_string(),
        level: level.to_string(),
        until: now + REFRESH_LIFE,
        access: hash(&token),
        spent: None,
        next: None,
    };
    let refresh_hash = hash(&refresh);
    let mut ops = Vec::new();
    if let (Ok(a), Ok(r)) = (serde_json::to_vec(&access), serde_json::to_vec(&renewed)) {
        ops.push(Op::Put(format!("{TOKENS}{}", hash(&token)), a));
        ops.push(Op::Put(format!("{REFRESH}{refresh_hash}"), r));
    }
    let answer = serde_json::json!({
        "access_token": token,
        "token_type": "bearer",
        "expires_in": TOKEN_LIFE,
        "refresh_token": refresh,
    });
    (answer, ops, refresh_hash)
}

/// The did:key an ed25519 seed names (QNTX internal/access MintToken).
fn did_of_seed(mut seed: [u8; 32]) -> String {
    match libp2p_identity::ed25519::SecretKey::try_from_bytes(&mut seed) {
        Ok(secret) => {
            let pair = libp2p_identity::ed25519::Keypair::from(secret);
            laye_me::didkey::encode(&pair.public().to_bytes())
        }
        Err(_) => String::new(),
    }
}

/// Every refresh token issued after a stolen one spent, and its access token
/// deleted. A spent one stays until it ends, so presented again it is
/// answered as laye's, and refused. How many.
async fn revoke_after(etcd: &Etcd, mut next: Option<String>, now: u64) -> usize {
    let mut revoked = 0;
    for _ in 0..CHAIN {
        let Some(at) = next.take() else { break };
        let key = format!("{REFRESH}{at}");
        let Ok(Some(kv)) = etcd.get(&key).await else {
            break;
        };
        let Ok(mut held) = serde_json::from_slice::<Refresh>(&kv.value) else {
            break;
        };
        next = held.next.take();
        held.spent.get_or_insert(now);
        let Ok(value) = serde_json::to_vec(&held) else {
            break;
        };
        let ops = vec![
            Op::Put(key.clone(), value),
            Op::Delete(format!("{TOKENS}{}", held.access)),
        ];
        if let Err(why) = etcd.txn(&[], ops).await {
            eprintln!(
                "laye-front: a refresh token issued after a stolen one was not revoked: {why}"
            );
            break;
        }
        revoked += 1;
    }
    revoked
}

/// Who a token is, to the node asking: a token laye issued a node, or one it
/// issued a connector for that node.
pub async fn introspect(laye: &Laye<'_>, etcd: &Etcd, body: &[u8]) -> Said {
    let asked = form(&String::from_utf8_lossy(body));
    let node = match laye.node_asking(&asked) {
        Ok(node) => node,
        Err(why) => return refused(401, "invalid_client", why),
    };
    let token = asked.get("token").map(String::as_str).unwrap_or_default();
    if let Some(said) = laye.held(&node, token) {
        return said;
    }
    let inactive = json(200, serde_json::json!({ "active": false }));
    let held = match etcd.get(&format!("{TOKENS}{}", hash(token))).await {
        Ok(Some(kv)) => match serde_json::from_slice::<Access>(&kv.value) {
            Ok(held) => held,
            Err(_) => return inactive,
        },
        Ok(None) => return inactive,
        // Not an answer: the node asks again, rather than holding it inactive.
        Err(why) => return refused(503, "temporarily_unavailable", why),
    };
    let client = match client(etcd, &held.client).await {
        Ok(Some(client)) => client,
        Ok(None) => return inactive,
        Err(why) => return refused(503, "temporarily_unavailable", why),
    };
    if held.until <= laye.now || client.node != node || !laye.still_as(&held.person, &held.level) {
        return inactive;
    }
    json(
        200,
        serde_json::json!({
            "active": true,
            "iss": laye.issuer,
            "sub": held.person,
            "client_id": client.did,
            "token_type": "bearer",
            "level": held.level,
            "did": held.did,
            "label": client.label,
            "namespaces": client.namespaces,
            "exp": held.until,
        }),
    )
}

/// Codes, tokens and refresh tokens past their end, deleted. Why any was not.
pub async fn sweep(etcd: &Etcd, now: u64) -> Vec<String> {
    let mut why = Vec::new();
    for prefix in [CODES, TOKENS, REFRESH] {
        let held = match etcd.under(prefix).await {
            Ok(held) => held,
            Err(e) => {
                why.push(e);
                continue;
            }
        };
        for (key, kv) in held {
            let ended = serde_json::from_slice::<Until>(&kv.value).is_ok_and(|u| u.until <= now);
            if ended
                && let Err(e) = etcd
                    .txn(&[(&key, kv.mod_revision)], vec![Op::Delete(key.clone())])
                    .await
            {
                why.push(e);
            }
        }
    }
    why
}
