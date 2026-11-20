//! Where QNTX's people log in: laye's screen, and the four addresses a node
//! that names laye as its primary asks (QNTX server/auth/login_elsewhere.go).

// "so laye owns login as well"
// "the lgin screen, you would be seeing laye"
// "and QNTX and a QNTX Node Namespaces, likewise delegate this out to laye"

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use laye_me::SignedBinding;

use crate::invitations::{Account, Invitations};
use crate::{door, jwt};

/// A node that logs its people in at laye: its did:key, and where they are
/// sent back to.
#[derive(Debug, Clone, Deserialize)]
pub struct Node {
    pub did: String,
    pub back: String,
}

const ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// What QNTX takes as a token (internal/access TokenPrefix).
const TOKEN_PREFIX: &str = "qntx_";
const CHALLENGE_LIFE: u64 = 120;
const CODE_LIFE: u64 = 60;
const TOKEN_LIFE: u64 = 3600;
const MAX_ASSERTION_LIFE: u64 = 300;

struct Code {
    node: String,
    back: String,
    challenge: String,
    identity: String,
    level: &'static str,
    did: String,
    until: u64,
}

struct Token {
    node: String,
    identity: String,
    level: &'static str,
    did: String,
    until: u64,
}

/// QNTX's levels (internal/access): a root, or somebody a root invited.
pub(crate) const ROOT: &str = "ROOT";
pub(crate) const USER: &str = "USER";

#[derive(Default)]
pub(crate) struct Issued {
    challenges: Mutex<HashMap<String, u64>>,
    codes: Mutex<HashMap<String, Code>>,
    tokens: Mutex<HashMap<String, Token>>,
    assertions: Mutex<HashMap<String, u64>>,
}

/// An answer: status, content type, body.
pub(crate) type Said = (u16, &'static str, String);

fn json(status: u16, value: serde_json::Value) -> Said {
    (status, "application/json", value.to_string())
}

fn refused(status: u16, error: &str, why: impl Into<String>) -> Said {
    json(
        status,
        serde_json::json!({ "error": error, "error_description": why.into() }),
    )
}

fn random_hex(n: usize) -> String {
    (0..n)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

fn hash(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A form or a query, decoded.
pub(crate) fn form(s: &str) -> HashMap<String, String> {
    s.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((decode(k), decode(v)))
        })
        .collect()
}

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            _ => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub(crate) struct Laye<'a> {
    pub issuer: &'a str,
    pub did: &'a str,
    pub nodes: &'a [Node],
    pub roots: &'a [String],
    pub signers: &'a [String],
    pub issued: &'a Issued,
    pub invitations: &'a Invitations,
    /// Where an account proves itself: the provider ceremony's origin.
    pub ceremony: &'a str,
    pub now: u64,
}

impl Laye<'_> {
    pub(crate) fn metadata(&self) -> Said {
        json(
            200,
            serde_json::json!({
                "issuer": self.issuer,
                "did": self.did,
                "authorization_endpoint": format!("{}/auth/authorize", self.issuer),
                "token_endpoint": format!("{}/auth/token", self.issuer),
                "introspection_endpoint": format!("{}/auth/introspect", self.issuer),
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
            }),
        )
    }

    /// The node a journey names, when laye knows it and it asks to be sent
    /// back where it is known to be.
    fn node_of(&self, asked: &HashMap<String, String>) -> Result<&Node, String> {
        let client = asked
            .get("client_id")
            .map(String::as_str)
            .unwrap_or_default();
        let back = asked
            .get("redirect_uri")
            .map(String::as_str)
            .unwrap_or_default();
        let node = self
            .nodes
            .iter()
            .find(|n| n.did == client)
            .ok_or_else(|| format!("laye logs nobody in for {client:?}"))?;
        if node.back != back {
            return Err(format!(
                "{client} is sent back to {}, not {back}",
                node.back
            ));
        }
        Ok(node)
    }

    /// laye's login screen.
    pub(crate) fn authorize(&self, query: &str) -> Said {
        let asked = form(query);
        if let Err(why) = self.node_of(&asked) {
            return refused(400, "invalid_client", why);
        }
        let s256 = asked.get("code_challenge_method").map(String::as_str) == Some("S256");
        let has_challenge = asked.get("code_challenge").is_some_and(|c| !c.is_empty());
        if !s256 || !has_challenge {
            return refused(400, "invalid_request", "laye takes a code challenge, S256");
        }
        self.page(Some(query))
    }

    /// Where the provider ceremony sends somebody back to: the same screen,
    /// with the journey the browser kept.
    pub(crate) fn back(&self) -> Said {
        self.page(None)
    }

    fn page(&self, journey: Option<&str>) -> Said {
        let page = include_str!("login.html")
            .replace(
                "{{authorize}}",
                &serde_json::to_string(&journey).unwrap_or_default(),
            )
            .replace(
                "{{ceremony}}",
                &serde_json::to_string(self.ceremony).unwrap_or_default(),
            );
        (200, "text/html; charset=utf-8", page)
    }

    pub(crate) fn challenge(&self) -> Said {
        let challenge = B64URL.encode(rand::random::<[u8; 32]>());
        let mut held = self
            .issued
            .challenges
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        held.retain(|_, until| *until > self.now);
        held.insert(challenge.clone(), self.now + CHALLENGE_LIFE);
        json(200, serde_json::json!({ "challenge": challenge }))
    }

    /// A login on laye's screen: the challenge laye issued, signed by a root,
    /// and the journey the node started. Answered with where to go back to.
    pub(crate) fn login(&self, body: &[u8]) -> Said {
        #[derive(Deserialize)]
        struct Journey {
            authorize: String,
        }
        let (Ok(presented), Ok(journey)) = (
            serde_json::from_slice::<door::Login>(body),
            serde_json::from_slice::<Journey>(body),
        ) else {
            return refused(400, "invalid_request", "the login does not read");
        };
        let fresh = self
            .issued
            .challenges
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&presented.challenge)
            .is_some_and(|until| until > self.now);
        if !fresh {
            return refused(
                401,
                "invalid_request",
                "laye issued no such challenge, or it is spent",
            );
        }
        let (identity, level) = match self.who_logs_in(&presented) {
            Ok(admitted) => admitted,
            Err(why) => return refused(403, "access_denied", why),
        };
        let asked = form(&journey.authorize);
        let node = match self.node_of(&asked) {
            Ok(node) => node.clone(),
            Err(why) => return refused(400, "invalid_client", why),
        };
        let code = random_hex(32);
        self.issued
            .codes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                code.clone(),
                Code {
                    node: node.did,
                    back: node.back.clone(),
                    challenge: asked.get("code_challenge").cloned().unwrap_or_default(),
                    identity,
                    level,
                    did: presented.did,
                    until: self.now + CODE_LIFE,
                },
            );
        let state = asked.get("state").cloned().unwrap_or_default();
        json(
            200,
            serde_json::json!({
                "redirect": format!("{}?code={}&state={}", node.back, encode(&code), encode(&state)),
            }),
        )
    }

    /// The node asking is the node it says, signing as its own key for laye's
    /// token address, once.
    fn node_asking(&self, asked: &HashMap<String, String>) -> Result<String, String> {
        if asked.get("client_assertion_type").map(String::as_str) != Some(ASSERTION) {
            return Err("a node asks by signing as its did:key".into());
        }
        let assertion = asked
            .get("client_assertion")
            .map(String::as_str)
            .unwrap_or_default();
        let claims = jwt::read(assertion).map_err(|e| e.to_string())?;
        let client = asked
            .get("client_id")
            .map(String::as_str)
            .unwrap_or_default();
        if claims.iss != client || claims.sub != client {
            return Err(format!(
                "the assertion is {}'s about {}, and the request names {client}",
                claims.iss, claims.sub
            ));
        }
        if !self.nodes.iter().any(|n| n.did == client) {
            return Err(format!("laye knows no node {client}"));
        }
        let token_address = format!("{}/auth/token", self.issuer);
        if !claims.aud.contains(&token_address) {
            return Err(format!(
                "the assertion is for {:?}, not {token_address}",
                claims.aud
            ));
        }
        if claims.exp <= self.now || claims.exp > self.now + MAX_ASSERTION_LIFE {
            return Err("the assertion is out of its time".into());
        }
        let mut spent = self
            .issued
            .assertions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        spent.retain(|_, until| *until > self.now);
        if spent.insert(claims.jti.clone(), claims.exp).is_some() {
            return Err(format!(
                "the assertion {} was already presented",
                claims.jti
            ));
        }
        Ok(client.to_string())
    }

    /// A code, spent once by the node it was issued for, holding the verifier.
    pub(crate) fn token(&self, body: &[u8]) -> Said {
        let asked = form(&String::from_utf8_lossy(body));
        let node = match self.node_asking(&asked) {
            Ok(node) => node,
            Err(why) => return refused(401, "invalid_client", why),
        };
        if asked.get("grant_type").map(String::as_str) != Some("authorization_code") {
            return refused(
                400,
                "unsupported_grant_type",
                "laye issues for a code alone",
            );
        }
        let code = asked.get("code").map(String::as_str).unwrap_or_default();
        let Some(held) = self
            .issued
            .codes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(code)
        else {
            return refused(
                400,
                "invalid_grant",
                "laye issued no such code, or it is spent",
            );
        };
        let verifier = asked
            .get("code_verifier")
            .map(String::as_str)
            .unwrap_or_default();
        let verified = B64URL.encode(Sha256::digest(verifier.as_bytes())) == held.challenge;
        let back = asked
            .get("redirect_uri")
            .map(String::as_str)
            .unwrap_or_default();
        if held.until <= self.now || held.node != node || held.back != back || !verified {
            return refused(
                400,
                "invalid_grant",
                "the code is not this node's, not for here, or the verifier is not its",
            );
        }
        let token = format!("{TOKEN_PREFIX}{}", random_hex(32));
        self.issued
            .tokens
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                hash(&token),
                Token {
                    node,
                    identity: held.identity,
                    level: held.level,
                    did: held.did,
                    until: self.now + TOKEN_LIFE,
                },
            );
        json(
            200,
            serde_json::json!({
                "access_token": token,
                "token_type": "bearer",
                "expires_in": TOKEN_LIFE,
            }),
        )
    }

    /// The challenge laye issued, spent once. Whether it was laye's and fresh.
    fn spend(&self, challenge: &str) -> bool {
        self.issued
            .challenges
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(challenge)
            .is_some_and(|until| until > self.now)
    }

    /// Who a login proves, for a passkey to be made on: a root, or the account
    /// an invitation lets in, and the binding that reached them. The binding is
    /// kept with the passkey, so laye asks it again at every sign-in without
    /// the ceremony that made it.
    pub(crate) fn first_half(
        &self,
        presented: &door::Login,
    ) -> Result<(String, &'static str, Option<SignedBinding>), (u16, String)> {
        if !self.spend(&presented.challenge) {
            return Err((401, "laye issued no such challenge, or it is spent".into()));
        }
        let vouched = door::vouched(presented, self.signers).map_err(|why| (403, why))?;
        if self.roots.contains(&presented.did) {
            return Ok((presented.did.clone(), ROOT, None));
        }
        if let Some(b) = vouched
            .iter()
            .find(|b| self.roots.contains(&b.claim.canonical_id))
        {
            return Ok((b.claim.canonical_id.clone(), ROOT, Some((*b).clone())));
        }
        match self.invitations.admit(&vouched) {
            Ok(Some(account)) => {
                let binding = vouched
                    .iter()
                    .find(|b| b.claim.canonical_id == account)
                    .map(|b| (*b).clone());
                Ok((account, USER, binding))
            }
            Ok(None) => Err((
                403,
                "nothing presented is a root, or an account a root invited".into(),
            )),
            Err(why) => Err((500, why)),
        }
    }

    /// Whether what a passkey was made on still holds, asked now: the binding
    /// still its signer's, the signer still trusted, the account still a root
    /// or still let in. Else why not.
    pub(crate) fn still_vouched(
        &self,
        person: &str,
        level: &str,
        binding: Option<&SignedBinding>,
    ) -> Result<(), String> {
        if let Some(b) = binding {
            b.verify().map_err(|e| {
                format!("the binding {person} was reached by no longer verifies: {e:?}")
            })?;
            if !self.signers.contains(&door::hex(&b.signer_pubkey)) {
                return Err(format!(
                    "the binding {person} was reached by is signed by a key laye no longer trusts"
                ));
            }
            if b.claim.canonical_id != person {
                return Err(format!(
                    "the binding kept is {}'s, not {person}'s",
                    b.claim.canonical_id
                ));
            }
        }
        let held =
            match level {
                ROOT => self.roots.iter().any(|r| r == person),
                USER => self.invitations.list().iter().any(|inv| {
                    inv.state() == "accepted" && inv.accepted_by.as_deref() == Some(person)
                }),
                _ => false,
            };
        if held {
            Ok(())
        } else {
            Err(format!(
                "{person} is no longer a root, or let in by an invitation"
            ))
        }
    }

    /// Who a token is, to the node it was issued for.
    pub(crate) fn introspect(&self, body: &[u8]) -> Said {
        let asked = form(&String::from_utf8_lossy(body));
        let node = match self.node_asking(&asked) {
            Ok(node) => node,
            Err(why) => return refused(401, "invalid_client", why),
        };
        let token = asked.get("token").map(String::as_str).unwrap_or_default();
        let tokens = self.issued.tokens.lock().unwrap_or_else(|p| p.into_inner());
        match tokens.get(&hash(token)) {
            Some(held) if held.until > self.now && held.node == node && self.still_in(held) => {
                json(
                    200,
                    serde_json::json!({
                        "active": true,
                        "iss": self.issuer,
                        "sub": held.identity,
                        "client_id": held.node,
                        "token_type": "bearer",
                        "level": held.level,
                        "did": held.did,
                        "label": "laye",
                    }),
                )
            }
            _ => json(200, serde_json::json!({ "active": false })),
        }
    }

    /// Who a login is: a root, or the account an invitation lets in.
    fn who_logs_in(&self, presented: &door::Login) -> Result<(String, &'static str), String> {
        if let Ok(root) = door::admitted_as(presented, self.roots, self.signers) {
            return Ok((root, ROOT));
        }
        let vouched = door::vouched(presented, self.signers)?;
        match self.invitations.admit(&vouched)? {
            Some(account) => Ok((account, USER)),
            None => Err("nothing presented is a root, or an account a root invited".into()),
        }
    }

    /// A token stands only while who it is still is: a root still listed, or
    /// an invited account not kicked.
    fn still_in(&self, held: &Token) -> bool {
        if held.level == ROOT {
            return self.roots.contains(&held.identity);
        }
        self.invitations.list().iter().any(|inv| {
            inv.state() == "accepted" && inv.accepted_by.as_deref() == Some(held.identity.as_str())
        })
    }

    /// A root's request about invitations: the signer is a root's own key.
    fn root_asking(&self, signer: Option<&str>) -> Result<String, Said> {
        match signer {
            Some(did) if self.roots.iter().any(|r| r == did) => Ok(did.to_string()),
            Some(did) => Err(refused(
                403,
                "access_denied",
                format!("{did} is not a root, and only a root invites"),
            )),
            None => Err(refused(
                401,
                "invalid_request",
                "a root signs what it asks of invitations",
            )),
        }
    }

    /// A root invites: the accounts the invited person may sign in with.
    pub(crate) fn invite(&self, signer: Option<&str>, body: &[u8]) -> Said {
        let root = match self.root_asking(signer) {
            Ok(root) => root,
            Err(said) => return said,
        };
        #[derive(Deserialize)]
        struct Asked {
            accounts: Vec<Account>,
        }
        let Ok(asked) = serde_json::from_slice::<Asked>(body) else {
            return refused(
                400,
                "invalid_request",
                "an invitation is {\"accounts\": [{\"provider\", \"account\"}]}",
            );
        };
        match self.invitations.invite(&root, asked.accounts, self.now) {
            Ok(inv) => json(200, serde_json::json!(inv)),
            Err(why) => refused(400, "invalid_request", why),
        }
    }

    /// A root cancels an invitation, or kicks the one it let in.
    pub(crate) fn withdraw(&self, signer: Option<&str>, body: &[u8]) -> Said {
        if let Err(said) = self.root_asking(signer) {
            return said;
        }
        #[derive(Deserialize)]
        struct Asked {
            id: String,
        }
        let Ok(asked) = serde_json::from_slice::<Asked>(body) else {
            return refused(400, "invalid_request", "a withdrawal is {\"id\"}");
        };
        match self.invitations.withdraw(&asked.id, self.now) {
            Ok(inv) => json(200, serde_json::json!(inv)),
            Err(why) => refused(400, "invalid_request", why),
        }
    }

    /// Every invitation, to a root.
    pub(crate) fn invitations(&self, signer: Option<&str>) -> Said {
        if let Err(said) = self.root_asking(signer) {
            return said;
        }
        let all: Vec<serde_json::Value> = self
            .invitations
            .list()
            .iter()
            .map(|inv| {
                let mut v = serde_json::json!(inv);
                if let Some(fields) = v.as_object_mut() {
                    fields.insert("state".into(), serde_json::json!(inv.state()));
                }
                v
            })
            .collect();
        json(200, serde_json::json!({ "invitations": all }))
    }

    /// Who administers the network, to a node laye logs people in for: the
    /// node reads its roots from laye, not from its own am.toml.
    pub(crate) fn roots(&self, body: &[u8]) -> Said {
        let asked = form(&String::from_utf8_lossy(body));
        if let Err(why) = self.node_asking(&asked) {
            return refused(401, "invalid_client", why);
        }
        json(200, serde_json::json!({ "root_identities": self.roots }))
    }
}
