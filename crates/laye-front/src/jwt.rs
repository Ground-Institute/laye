//! The signature a request carries: a JWT its signer made for one request,
//! EdDSA by the key its issuer's did:key names. The same shape ground signs
//! with and QNTX reads (server/auth/signed.go).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use laye_me::Keypair;
use serde::{Deserialize, Deserializer, Serialize};

const HEADER: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    #[serde(deserialize_with = "one_or_many")]
    pub aud: Vec<String>,
    pub exp: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub iat: u64,
    pub jti: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// A JWT names its audience as one string or a list of them.
fn one_or_many<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Aud {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Aud::deserialize(d)? {
        Aud::One(one) => vec![one],
        Aud::Many(many) => many,
    })
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum JwtError {
    #[error("a JWT is three parts joined by dots")]
    NotThreeParts,
    #[error("the {0} does not read: {1}")]
    Unreadable(&'static str, String),
    #[error("the JWT is signed with {0}, and laye reads EdDSA alone")]
    NotEdDsa(String),
    #[error("the issuer {iss} is not a did:key: {why}")]
    NotAKey { iss: String, why: String },
    #[error("the signature is not {0}'s")]
    NotItsSignature(String),
    #[error("signing failed: {0}")]
    Sign(String),
}

/// A JWT signed by `key`, saying `claims`.
pub fn sign(key: &Keypair, claims: &Claims) -> Result<String, JwtError> {
    let payload =
        serde_json::to_vec(claims).map_err(|e| JwtError::Unreadable("claims", e.to_string()))?;
    let input = format!("{}.{}", B64.encode(HEADER), B64.encode(payload));
    let signature = key
        .sign(input.as_bytes())
        .map_err(|e| JwtError::Sign(e.to_string()))?;
    Ok(format!("{input}.{}", B64.encode(signature)))
}

/// The claims of a JWT whose signature is its issuer's. Nothing else is
/// checked here: whom it is for, and until when, are the reader's to ask.
pub fn read(token: &str) -> Result<Claims, JwtError> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::NotThreeParts);
    };
    let header: serde_json::Value = decode("header", header)?;
    let alg = header
        .get("alg")
        .and_then(|a| a.as_str())
        .unwrap_or_default();
    if alg != "EdDSA" {
        return Err(JwtError::NotEdDsa(alg.to_string()));
    }
    let claims: Claims = decode("claims", payload)?;
    let key = laye_me::didkey::decode(&claims.iss).map_err(|e| JwtError::NotAKey {
        iss: claims.iss.clone(),
        why: e.to_string(),
    })?;
    let public = libp2p_identity::ed25519::PublicKey::try_from_bytes(&key).map_err(|e| {
        JwtError::NotAKey {
            iss: claims.iss.clone(),
            why: e.to_string(),
        }
    })?;
    let signature = B64
        .decode(signature)
        .map_err(|e| JwtError::Unreadable("signature", e.to_string()))?;
    let input_len = token.len() - signature_len(token);
    let input = token.get(..input_len).unwrap_or_default();
    if !public.verify(input.as_bytes(), &signature) {
        return Err(JwtError::NotItsSignature(claims.iss));
    }
    Ok(claims)
}

/// How many bytes the signature part and the dot before it take.
fn signature_len(token: &str) -> usize {
    token.rfind('.').map(|at| token.len() - at).unwrap_or(0)
}

fn decode<T: for<'de> Deserialize<'de>>(what: &'static str, part: &str) -> Result<T, JwtError> {
    let bytes = B64
        .decode(part)
        .map_err(|e| JwtError::Unreadable(what, e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| JwtError::Unreadable(what, e.to_string()))
}

/// A JWT id: sixteen random bytes in hex, which is what QNTX takes.
pub fn fresh_jti() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
