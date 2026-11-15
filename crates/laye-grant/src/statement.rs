//! What one key says, signed over the bytes that are carried.

use crate::wire::{Claim, Statement, claim::Says};
use laye_me::{Keypair, didkey};
use prost::Message;
use sha2::{Digest, Sha256};

/// A statement's id: the sha256 of its claim.
pub type Id = [u8; 32];

/// What is signed is this and then the claim, so a signature made for laye is
/// a signature for nothing else.
const PREFIX: &[u8] = b"laye-claim/v1|";

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum StatementError {
    #[error("the key is not an ed25519 key: {0}")]
    NotEd25519(String),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("the signer {signer:?} is not a key: {why}")]
    Signer { signer: String, why: String },
    #[error("the signature is not {signer}'s over this claim")]
    Signature { signer: String },
    #[error("the claim does not read: {0}")]
    Claim(String),
    #[error("the claim says nothing")]
    Empty,
}

/// The did:key a keypair is.
pub fn did_of(keypair: &Keypair) -> Result<String, StatementError> {
    let ed25519 = keypair
        .public()
        .try_into_ed25519()
        .map_err(|e| StatementError::NotEd25519(e.to_string()))?;
    Ok(didkey::encode(&ed25519.to_bytes()))
}

fn signed_bytes(claim: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(PREFIX.len() + claim.len());
    signed.extend_from_slice(PREFIX);
    signed.extend_from_slice(claim);
    signed
}

/// A statement by this key, saying this.
pub fn sign(keypair: &Keypair, says: Says) -> Result<Statement, StatementError> {
    let claim = Claim { says: Some(says) }.encode_to_vec();
    let signature = keypair
        .sign(&signed_bytes(&claim))
        .map_err(|e| StatementError::Sign(e.to_string()))?;
    Ok(Statement {
        claim,
        signature,
        signer: did_of(keypair)?,
    })
}

/// A statement whose signature held: who said it, what, and its id.
#[derive(Debug, Clone, PartialEq)]
pub struct Said {
    pub id: Id,
    pub signer: String,
    pub says: Says,
}

/// The statement, read: its signature is its signer's over the bytes carried,
/// and its claim says something. Nothing is encoded again to check it.
pub fn read(statement: &Statement) -> Result<Said, StatementError> {
    let key = didkey::decode(&statement.signer).map_err(|e| StatementError::Signer {
        signer: statement.signer.clone(),
        why: e.to_string(),
    })?;
    let public = libp2p_identity::ed25519::PublicKey::try_from_bytes(&key).map_err(|e| {
        StatementError::Signer {
            signer: statement.signer.clone(),
            why: e.to_string(),
        }
    })?;
    if !public.verify(&signed_bytes(&statement.claim), &statement.signature) {
        return Err(StatementError::Signature {
            signer: statement.signer.clone(),
        });
    }
    let claim = Claim::decode(statement.claim.as_slice())
        .map_err(|e| StatementError::Claim(e.to_string()))?;
    let says = claim.says.ok_or(StatementError::Empty)?;
    Ok(Said {
        id: id_of(statement),
        signer: statement.signer.clone(),
        says,
    })
}

pub fn id_of(statement: &Statement) -> Id {
    Sha256::digest(&statement.claim).into()
}

/// The hash of a stretch: its bodies in order, each after its length as eight
/// bytes, the highest first.
pub fn digest(bodies: &[Vec<u8>]) -> Id {
    let mut hasher = Sha256::new();
    for body in bodies {
        hasher.update((body.len() as u64).to_be_bytes());
        hasher.update(body);
    }
    hasher.finalize().into()
}
