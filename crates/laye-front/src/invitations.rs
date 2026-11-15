//! Who a root let in: the invitations laye holds.

// "the network is invite only"
// "and i own the invites"
// "and i can kick anyone off for whatever reason"
// "my did is one of the did's that is allowed to hold authority over invites, because its like part of laye deployment code. which is a different repo from the public laye repo"
// "for inviting someone, the user story already exists in a way"

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use laye_me::SignedBinding;
use serde::{Deserialize, Serialize};

/// One provider the invited person may sign in with, and their account there:
/// an address, a username, or the provider's id for them. As QNTX's
/// InvitationAccount.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Account {
    pub provider: String,
    pub account: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Invitation {
    pub id: String,
    pub accounts: Vec<Account>,
    pub invited_by: String,
    pub created_at: u64,
    #[serde(default)]
    pub cancelled_at: Option<u64>,
    /// The account it let in, once somebody signed in on it.
    #[serde(default)]
    pub accepted_by: Option<String>,
    /// Kicked: the one it let in is out.
    #[serde(default)]
    pub kicked_at: Option<u64>,
}

impl Invitation {
    pub fn state(&self) -> &'static str {
        if self.kicked_at.is_some() {
            "kicked"
        } else if self.cancelled_at.is_some() {
            "cancelled"
        } else if self.accepted_by.is_some() {
            "accepted"
        } else {
            "open"
        }
    }

    /// The account a binding is, when this invitation names it: the same
    /// provider, and the account by its id or the handle the provider vouched.
    fn names(&self, binding: &SignedBinding) -> Option<String> {
        let claim = &binding.claim;
        let handle = claim.handle.as_deref().unwrap_or_default();
        self.accounts
            .iter()
            .any(|a| {
                a.provider == claim.provider
                    && (a.account.eq_ignore_ascii_case(&claim.canonical_id)
                        || (!handle.is_empty() && a.account.eq_ignore_ascii_case(handle)))
            })
            .then(|| claim.canonical_id.clone())
    }

    /// Whether this invitation lets this binding in: open and naming it, or
    /// accepted by that very account and not kicked.
    fn lets_in(&self, binding: &SignedBinding) -> Option<String> {
        let account = self.names(binding)?;
        match self.state() {
            "open" => Some(account),
            "accepted" if self.accepted_by.as_deref() == Some(account.as_str()) => Some(account),
            _ => None,
        }
    }
}

pub(crate) struct Invitations {
    at: PathBuf,
    held: Mutex<Vec<Invitation>>,
}

impl Invitations {
    pub(crate) fn load(at: &Path) -> Result<Self, String> {
        let held = match std::fs::read_to_string(at) {
            Ok(text) => text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str(l).map_err(|e| format!("{}: {e}", at.display())))
                .collect::<Result<Vec<_>, _>>()?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("{}: {e}", at.display())),
        };
        Ok(Self {
            at: at.to_path_buf(),
            held: Mutex::new(held),
        })
    }

    fn save(&self, all: &[Invitation]) -> Result<(), String> {
        let mut text = String::new();
        for inv in all {
            text.push_str(&serde_json::to_string(inv).map_err(|e| e.to_string())?);
            text.push('\n');
        }
        let mut beside = self.at.as_os_str().to_owned();
        beside.push(".new");
        std::fs::write(&beside, text).map_err(|e| format!("{}: {e}", self.at.display()))?;
        std::fs::rename(&beside, &self.at).map_err(|e| format!("{}: {e}", self.at.display()))
    }

    /// Changes all that is held, and keeps it, or leaves it as it was.
    fn change<T>(
        &self,
        f: impl FnOnce(&mut Vec<Invitation>) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        let mut next = held.clone();
        let out = f(&mut next)?;
        self.save(&next)?;
        *held = next;
        Ok(out)
    }

    pub(crate) fn list(&self) -> Vec<Invitation> {
        self.held.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub(crate) fn invite(
        &self,
        by: &str,
        accounts: Vec<Account>,
        now: u64,
    ) -> Result<Invitation, String> {
        if accounts.is_empty()
            || accounts
                .iter()
                .any(|a| a.provider.is_empty() || a.account.is_empty())
        {
            return Err("an invitation names at least one provider and the account there".into());
        }
        let inv = Invitation {
            id: (0..16)
                .map(|_| format!("{:02x}", rand::random::<u8>()))
                .collect(),
            accounts,
            invited_by: by.to_string(),
            created_at: now,
            cancelled_at: None,
            accepted_by: None,
            kicked_at: None,
        };
        let kept = inv.clone();
        self.change(|all| {
            all.push(kept);
            Ok(())
        })?;
        Ok(inv)
    }

    /// Cancels an invitation nobody signed in on yet, or kicks the one who did.
    pub(crate) fn withdraw(&self, id: &str, now: u64) -> Result<Invitation, String> {
        self.change(|all| {
            let inv = all
                .iter_mut()
                .find(|i| i.id == id)
                .ok_or_else(|| format!("laye holds no invitation {id}"))?;
            match inv.state() {
                "open" => inv.cancelled_at = Some(now),
                "accepted" => inv.kicked_at = Some(now),
                state => return Err(format!("invitation {id} is {state} already")),
            }
            Ok(inv.clone())
        })
    }

    /// The account an invitation lets in among the bindings presented, which
    /// is from then on the one that invitation is for.
    pub(crate) fn admit(&self, vouched: &[&SignedBinding]) -> Result<Option<String>, String> {
        self.change(|all| {
            for inv in all.iter_mut() {
                for binding in vouched {
                    if let Some(account) = inv.lets_in(binding) {
                        inv.accepted_by = Some(account.clone());
                        return Ok(Some(account));
                    }
                }
            }
            Ok(None)
        })
    }
}
