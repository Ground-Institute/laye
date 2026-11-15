#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::string_slice
    )
)]
//! The carve-out, running: a grant, handed to an agent, asked under, and
//! answered by its keeper. The contract is proto/laye/v1/laye.proto.

/// The contract's own types, built from it.
#[allow(clippy::all, clippy::restriction, clippy::pedantic)]
pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/laye.v1.rs"));
}

mod keeper;
mod statement;

pub use keeper::{Answer, HoldError, Keeper, Record};
pub use statement::{Id, Said, StatementError, did_of, digest, id_of, read, sign};
