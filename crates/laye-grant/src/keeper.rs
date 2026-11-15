//! The keeper: holds a person's grants, and answers what is asked under them.

use std::collections::{HashMap, HashSet};

use laye_me::Keypair;

use crate::statement::{Id, StatementError, did_of, digest, id_of, read, sign};
use crate::wire::{self, Kind, Narrow, Opens, State, Statement, Why, claim::Says, grant::To};

/// How far an Ask's time may be from the keeper's clock, in seconds.
const IN_TIME: u64 = 300;

/// An agent's record on one repository, as its keeper holds it.
pub trait Record {
    /// The bodies after a position, in order.
    fn after(&self, agent: &str, about: &str, after: u64) -> Vec<Vec<u8>>;
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum HoldError {
    #[error(transparent)]
    Statement(#[from] StatementError),
    #[error("the statement is not a grant")]
    NotAGrant,
    #[error("the statement is not a revoke")]
    NotARevoke,
    #[error("the grant is signed by {signer}, and its giver is {giver}")]
    NotTheGiver { signer: String, giver: String },
    #[error("the grant names the keeper {named}, and this is {this}")]
    NotThisKeeper { named: String, this: String },
    #[error("a statement's id is 32 bytes, and this is {0}")]
    NotAnId(usize),
    #[error("revoked by {signer}, who did not sign what it revokes")]
    NotItsSigner { signer: String },
}

/// What a keeper does with an Ask.
#[derive(Debug)]
pub enum Answer {
    Served {
        served: Statement,
        bodies: Vec<Vec<u8>>,
        /// Said when serving this pinned the grant.
        stands: Option<Statement>,
    },
    Refused(Statement),
    /// The Ask or its Grant did not verify, and gets no answer.
    Silent,
}

struct Held {
    grant: wire::Grant,
    state: State,
    /// PINNED and SPENT: the agent it is pinned to, its hand, and the Served
    /// that pinned it.
    agent: String,
    hand: Option<Id>,
    served: Option<Id>,
}

pub struct Keeper {
    key: Keypair,
    did: String,
    grants: HashMap<Id, Held>,
    /// What was revoked that is not a grant held here, and by whom.
    revoked: HashMap<Id, String>,
    seen: HashSet<Id>,
}

fn as_id(bytes: &[u8]) -> Option<Id> {
    bytes.try_into().ok()
}

fn person_of(grant: &wire::Grant) -> Option<&str> {
    match &grant.to {
        Some(To::Person(person)) => Some(person),
        _ => None,
    }
}

impl Keeper {
    pub fn new(key: Keypair) -> Result<Self, StatementError> {
        let did = did_of(&key)?;
        Ok(Self {
            key,
            did,
            grants: HashMap::new(),
            revoked: HashMap::new(),
            seen: HashSet::new(),
        })
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    /// The giver's grant, kept. It is GIVEN.
    pub fn hold(&mut self, grant: &Statement) -> Result<Id, HoldError> {
        let said = read(grant)?;
        let Says::Grant(g) = said.says else {
            return Err(HoldError::NotAGrant);
        };
        if said.signer != g.giver {
            return Err(HoldError::NotTheGiver {
                signer: said.signer,
                giver: g.giver,
            });
        }
        if g.keeper != self.did {
            return Err(HoldError::NotThisKeeper {
                named: g.keeper,
                this: self.did.clone(),
            });
        }
        self.grants.entry(said.id).or_insert(Held {
            grant: g,
            state: State::Given,
            agent: String::new(),
            hand: None,
            served: None,
        });
        Ok(said.id)
    }

    pub fn state(&self, grant: &Id) -> Option<State> {
        self.grants.get(grant).map(|held| held.state)
    }

    /// A Revoke, kept. A grant its giver revoked is REVOKED; a grant pinned
    /// to a hand its person revoked is SPENT. The Stands is what changed.
    pub fn revoke(&mut self, revoke: &Statement, now: u64) -> Result<Option<Statement>, HoldError> {
        let said = read(revoke)?;
        let Says::Revoke(r) = said.says else {
            return Err(HoldError::NotARevoke);
        };
        let id = as_id(&r.statement).ok_or(HoldError::NotAnId(r.statement.len()))?;

        if let Some(held) = self.grants.get_mut(&id) {
            if said.signer != held.grant.giver {
                return Err(HoldError::NotItsSigner {
                    signer: said.signer,
                });
            }
            held.state = State::Revoked;
            return Ok(self.say_stands(&id, now)?);
        }

        self.revoked.insert(id, said.signer.clone());
        let spent = self.grants.iter_mut().find_map(|(grant, held)| {
            let theirs = person_of(&held.grant) == Some(said.signer.as_str());
            if held.state == State::Pinned && held.hand == Some(id) && theirs {
                held.state = State::Spent;
                Some(*grant)
            } else {
                None
            }
        });
        match spent {
            Some(grant) => Ok(self.say_stands(&grant, now)?),
            None => Ok(None),
        }
    }

    /// An Ask, answered. `grant` is the Grant when it came with the Ask;
    /// `hand` the Hand when one did.
    pub fn ask(
        &mut self,
        ask: &Statement,
        grant: Option<&Statement>,
        hand: Option<&Statement>,
        record: &dyn Record,
        now: u64,
    ) -> Result<Answer, StatementError> {
        let Ok(said) = read(ask) else {
            return Ok(Answer::Silent);
        };
        let Says::Ask(a) = &said.says else {
            return Ok(Answer::Silent);
        };
        if said.signer != a.reader {
            return Ok(Answer::Silent);
        }
        let Some(grant_id) = as_id(&a.grant) else {
            return Ok(Answer::Silent);
        };
        if !self.grants.contains_key(&grant_id) {
            let Some(presented) = grant else {
                return Ok(Answer::Silent);
            };
            match self.hold(presented) {
                Ok(id) if id == grant_id => {}
                Err(HoldError::NotThisKeeper { .. }) => {
                    return self.refuse(said.id, Why::NotThisKeeper, now);
                }
                _ => return Ok(Answer::Silent),
            }
        }

        let hand_id = match self.check(&grant_id, &said.id, a, hand, now) {
            Ok(hand_id) => hand_id,
            Err(why) => return self.refuse(said.id, why, now),
        };
        let Some(held) = self.grants.get(&grant_id) else {
            return Ok(Answer::Silent);
        };
        let bodies = if held.grant.opens() == Opens::Record {
            record.after(&held.grant.of, &held.grant.about, a.after)
        } else {
            Vec::new()
        };
        let served = sign(
            &self.key,
            Says::Served(wire::Served {
                ask: said.id.to_vec(),
                after: a.after,
                upto: a.after + bodies.len() as u64,
                digest: digest(&bodies).to_vec(),
                issued_at: now,
            }),
        )?;
        self.seen.insert(said.id);

        let mut pinned = false;
        if let Some(held) = self.grants.get_mut(&grant_id) {
            let to_a_person = person_of(&held.grant).is_some();
            if held.state == State::Given && to_a_person && held.grant.narrow() == Narrow::First {
                held.state = State::Pinned;
                held.agent = a.reader.clone();
                held.hand = hand_id;
                held.served = Some(id_of(&served));
                pinned = true;
            }
        }
        let stands = if pinned {
            self.say_stands(&grant_id, now)?
        } else {
            None
        };
        Ok(Answer::Served {
            served,
            bodies,
            stands,
        })
    }

    /// What an Ask needs, in the contract's order. The first that does not
    /// hold is the Why. Ok is the Hand it came with, when the grant is to a
    /// person.
    fn check(
        &mut self,
        grant_id: &Id,
        ask_id: &Id,
        a: &wire::Ask,
        hand: Option<&Statement>,
        now: u64,
    ) -> Result<Option<Id>, Why> {
        let Some(held) = self.grants.get_mut(grant_id) else {
            return Err(Why::NotThisKeeper);
        };
        let g = held.grant.clone();
        if g.kind() != Kind::Read {
            return Err(Why::NotARead);
        }
        if g.opens() == Opens::Unspecified || g.about.is_empty() {
            return Err(Why::OpensNothing);
        }
        if held.state == State::Revoked {
            return Err(Why::RevokedGrant);
        }
        if g.until != 0 && now >= g.until {
            held.state = State::Ended;
        }
        if held.state == State::Ended {
            return Err(Why::EndedGrant);
        }
        if held.state == State::Spent {
            return Err(Why::SpentGrant);
        }
        if held.state == State::Pinned && held.agent != a.reader {
            return Err(Why::PinnedToAnother);
        }

        let hand_id = match &g.to {
            Some(To::Person(person)) => {
                let Some(Ok(h_said)) = hand.map(read) else {
                    return Err(Why::NotHanded);
                };
                let Says::Hand(h) = &h_said.says else {
                    return Err(Why::NotHanded);
                };
                let names_this = as_id(&h.grant) == Some(*grant_id);
                let asked_with = as_id(&a.hand) == Some(h_said.id);
                if h_said.signer != *person || !names_this || !asked_with {
                    return Err(Why::NotHanded);
                }
                if self.revoked.get(&h_said.id) == Some(person) {
                    return Err(Why::RevokedHand);
                }
                if h.until != 0 && now >= h.until {
                    if held.state == State::Pinned {
                        held.state = State::Spent;
                    }
                    return Err(Why::EndedHand);
                }
                if h.agent != a.reader {
                    return Err(Why::NotTheAgent);
                }
                Some(h_said.id)
            }
            Some(To::Agent(agent)) => {
                if *agent != a.reader {
                    return Err(Why::NotTheAgent);
                }
                None
            }
            None => return Err(Why::NotTheAgent),
        };

        if self.seen.contains(ask_id) {
            return Err(Why::SeenBefore);
        }
        if now.abs_diff(a.issued_at) > IN_TIME {
            return Err(Why::OutOfTime);
        }
        Ok(hand_id)
    }

    fn refuse(&self, ask: Id, why: Why, now: u64) -> Result<Answer, StatementError> {
        let refused = sign(
            &self.key,
            Says::Refused(wire::Refused {
                ask: ask.to_vec(),
                why: why as i32,
                issued_at: now,
            }),
        )?;
        Ok(Answer::Refused(refused))
    }

    fn say_stands(&self, grant: &Id, now: u64) -> Result<Option<Statement>, StatementError> {
        let Some(held) = self.grants.get(grant) else {
            return Ok(None);
        };
        let stands = sign(
            &self.key,
            Says::Stands(wire::Stands {
                grant: grant.to_vec(),
                state: held.state as i32,
                agent: held.agent.clone(),
                served: held.served.map(|id| id.to_vec()).unwrap_or_default(),
                issued_at: now,
            }),
        )?;
        Ok(Some(stands))
    }
}
