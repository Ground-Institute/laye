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
    did: String,
    until: u64,
}

struct Token {
    node: String,
    identity: String,
    did: String,
    until: u64,
}

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
        let page = include_str!("login.html").replace(
            "{{authorize}}",
            &serde_json::to_string(query).unwrap_or_default(),
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
        let identity = match door::admitted_as(&presented, self.roots, self.signers) {
            Ok(identity) => identity,
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
            Some(held) if held.until > self.now && held.node == node => json(
                200,
                serde_json::json!({
                    "active": true,
                    "iss": self.issuer,
                    "sub": held.identity,
                    "client_id": held.node,
                    "token_type": "bearer",
                    "level": "root",
                    "did": held.did,
                    "label": "laye",
                }),
            ),
            _ => json(200, serde_json::json!({ "active": false })),
        }
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
