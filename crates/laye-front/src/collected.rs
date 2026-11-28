//! What an agent says to an agent, collected by laye: kept in etcd as what
//! that one agent said to that other, delivered together when it is due or
//! when a person releases it, and received when that agent asks for it.

// "i want laye to also be tht A2A layer collections get placed into and be added or removed from and be released."
// "Agents cant wake Agents willy nilly"
// "the messages collect"
// "and as a human i can dial it"
// "and as a human i can observe it"
//
// "i expect in my mentalmodel to have multiple pending individual collections"
// "i want QNTX to do what laye says"
//
// A collection is its own: what one agent said to one other, under an id, at
// /collected/<laye's DID>/<the agent it waits for>/<its id>, with its own time.
// Each is in the shape `collected list` answers, so mycelia, `ground
// collected` and ag read it as they read a node's. A delivery is
// news on the row of the person the agent's key speaks for; it is received
// when the agent itself asks for the whole of it. Only a person's passkey
// session holds, releases, passes on, cancels or edits.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::devices;
use crate::etcd::{Etcd, Op};

/// Where what waits for each agent is kept: `/collected/<laye DID>/<agent DID>`.
pub const COLLECTED: &str = "/collected/";
/// What waits on a person's row: `/news/<id>`.
pub const NEWS: &str = "/news/";
/// The Tasks laye answered with: `/tasks/<id>`.
pub const TASKS: &str = "/tasks/";
/// How long what is collected waits: the longest QNTX names (waitOf), as laye
/// holds no agent's model.
pub const WAIT: u64 = 6 * 3600;
/// How long a delivery stands on the row for its agent to take.
const ON_THE_ROW: u64 = 24 * 3600;
/// How often a write is tried again when another laye wrote between.
const TRIES: usize = 5;
/// The row's symbol for what went well (QNTX statusline SymbolWell).
const WELL: &str = "+";

/// One thing an agent said, as `collected list` says it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Said {
    pub from: String,
    pub says: String,
    pub at: String,
    pub task: String,
    pub id: String,
    pub edited: bool,
    pub from_did: String,
    /// What the agent said, where laye took something out of it before it was
    /// kept (wire.rs): what is delivered is `says`, and this is the record.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub as_said: String,
    /// A reach line the agent asks the person to write on a node. Approved,
    /// laye has the node's primary write it as the person (lib.rs, reach_approved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach: Option<Reach>,
    /// A key the node holds nothing for, to admit. Approved, laye has the
    /// node's primary admit it as the person (lib.rs, reach_approved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admit: Option<Admit>,
    /// What wakes nobody: it makes nothing due, and goes with the next
    /// delivery (QNTX collectedSaid.Quiet, a delivery of GitHub's).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub quiet: bool,
    /// The A2UI messages said beside `says`, as they were said (a2ui.rs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub a2ui: Vec<Value>,
}

impl Said {
    /// Whether this waits on the person's approve or deny, the thing itself.
    pub fn approval(&self) -> bool {
        self.reach.is_some() || self.admit.is_some()
    }
}

/// "SESSION CANT REACH, IT NEEDS REACH LINE(S), IT GETS IN FRONT OF MY VIA AG OR LIVE ACTIVITY AS SOMETHING TO APPROVE,"
///
/// The reach a refused request lacked, on the node that refused it:
/// `REACH is '<path>' of <to>`, made from the refusal.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Reach {
    /// The node that refused, by its did:key.
    pub peer: String,
    pub path: String,
    pub to: String,
}

impl Reach {
    /// The line, as it reads.
    pub fn line(&self) -> String {
        format!("REACH is '{}' of {}", self.path, self.to)
    }
}

/// "CAN WE PLEASE STOP EXPECTING AN AGENT TO REQUEST IT OWN PERMISSIONS AND ALSO BE PERFECT?"
/// "yeah, it jus tfeels like this should happen for sure"
///
/// A key that signed as itself for a node that holds nothing for it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Admit {
    /// The node that holds nothing for it, by its did:key.
    pub peer: String,
    /// The key, by its did:key.
    pub did: String,
    /// What it calls itself.
    pub label: String,
}

impl Admit {
    /// What admitting it reads as.
    pub fn line(&self) -> String {
        if self.label.is_empty() {
            format!("admit the key {}", self.did)
        } else {
            format!("admit {}'s key {}", self.label, self.did)
        }
    }
}

/// What a node asks its person to approve.
#[derive(Clone, Debug, PartialEq)]
pub enum Ask {
    Reach(Reach),
    Admit(Admit),
}

impl Ask {
    /// What it reads as.
    pub fn line(&self) -> String {
        match self {
            Ask::Reach(r) => r.line(),
            Ask::Admit(a) => a.line(),
        }
    }

    /// What names the collection this ask begins: the node that asks it and
    /// what it asks, the same for the same ask.
    pub fn id(&self) -> String {
        let sum = Sha256::digest(format!("{}\n{}", self.peer(), self.line()).as_bytes());
        sum.iter().take(8).map(|b| format!("{b:02x}")).collect()
    }

    /// The node that asks it.
    fn peer(&self) -> &str {
        match self {
            Ask::Reach(r) => &r.peer,
            Ask::Admit(a) => &a.peer,
        }
    }

    /// Whether said is this very ask, waiting.
    fn waits_in(&self, said: &Said) -> bool {
        match self {
            Ask::Reach(r) => said.reach.as_ref() == Some(r),
            Ask::Admit(a) => said.admit.as_ref() == Some(a),
        }
    }
}

/// What waits for one agent, as `collected list` says it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Collected {
    /// What names it among what waits for the same agent.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// Who said what it holds.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from_did: String,
    pub to: String,
    pub did: String,
    pub model: String,
    pub waits: String,
    pub due: String,
    pub held_until: String,
    pub delivered: String,
    pub waiting: Vec<Said>,
    pub failing_since: String,
    pub tries: i32,
    pub failure: String,
    /// Whose it is, where a refusal named them: an asker laye never admitted
    /// still waits on the person it stands for.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub person: String,
    /// What waits for an agent the node itself runs, its Node Agent: what is
    /// released goes to the node, which runs it as the agent's turn.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub node: bool,
}

/// Whose a collected thing is, past who it is for: the person who sees it,
/// whether the node runs the agent, and whether it wakes it.
#[derive(Clone, Debug, Default)]
pub struct Whose {
    pub person: String,
    pub node: bool,
    pub quiet: bool,
}

/// A Task laye answered with, and where it is.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tasked {
    pub id: String,
    pub context: String,
    /// TASK_STATE_*, as 1.0 says it.
    pub state: String,
    /// Why it is where it is.
    pub says: String,
    pub to: String,
    pub did: String,
}

/// A delivery, on a person's row until its agent takes it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct News {
    pub id: String,
    /// The person whose row it is on.
    #[serde(rename = "for")]
    pub for_person: String,
    pub name: String,
    pub note: String,
    pub to: String,
    pub did: String,
    pub from: String,
    /// The Tasks of what it delivers, completed when it is received.
    pub tasks: Vec<String>,
    pub until: u64,
    /// For the node's own agent: laye hands it to the node (lib.rs, hand_to_node).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub node: bool,
}

pub fn stamp(at: u64) -> String {
    if at == 0 {
        return String::new();
    }
    i64::try_from(at)
        .ok()
        .and_then(|s| DateTime::<Utc>::from_timestamp(s, 0))
        .map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_default()
}

pub fn secs(stamped: &str) -> u64 {
    DateTime::parse_from_rfc3339(stamped)
        .ok()
        .and_then(|t| u64::try_from(t.timestamp()).ok())
        .unwrap_or(0)
}

fn fresh_id() -> String {
    (0..8)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

/// A Task's id, as a2a-go mints one: a UUID.
fn task_id() -> String {
    let bytes: [u8; 16] = rand::random();
    let mut id = String::with_capacity(36);
    for (at, byte) in bytes.iter().enumerate() {
        if matches!(at, 4 | 6 | 8 | 10) {
            id.push('-');
        }
        id.push_str(&format!("{byte:02x}"));
    }
    id
}

impl Collected {
    /// What names it among everything laye collected: the agent it waits for,
    /// and its id. One kept before a collection had an id is its agent's.
    pub fn named(&self) -> String {
        if self.id.is_empty() {
            self.did.clone()
        } else {
            format!("{}/{}", self.did, self.id)
        }
    }

    /// When what waits is delivered if nobody holds or releases it, as QNTX's
    /// `due`: the wait after the first of it, no sooner than the wait after the
    /// last delivery, and no sooner than a person held it to.
    fn due_at(&self) -> u64 {
        // What wakes nobody makes nothing due.
        let Some(first) = self.waiting.iter().find(|s| !s.quiet) else {
            return 0;
        };
        let mut due = secs(&first.at) + WAIT;
        let delivered = secs(&self.delivered);
        if delivered > 0 {
            due = due.max(delivered + WAIT);
        }
        due.max(secs(&self.held_until))
    }

    fn settle(&mut self) {
        self.waits = "6h0m0s".into();
        self.due = stamp(self.due_at());
    }
}

/// Everything that waits, as the one thing said to the agent (QNTX `asOneThing`).
fn as_one_thing(waiting: &[Said]) -> String {
    let since = waiting.first().map_or("", |s| s.at.as_str());
    let mut said =
        format!("Collected for you: what agents said to you since {since}, delivered together.");
    if waiting.iter().any(|s| s.edited) {
        said.push_str(" A person changed what is marked so.\n");
    } else {
        said.push_str(" No person said any of it.\n");
    }
    for one in waiting {
        let changed = if one.edited {
            ", changed by a person"
        } else {
            ""
        };
        said.push_str(&format!(
            "\n{}, {}{changed}:\n{}\n",
            one.from, one.at, one.says
        ));
    }
    said
}

/// Why what was said is not said to the agent now (QNTX `collectedSays`).
fn collected_says(called: &str, due: u64) -> String {
    format!(
        "collected for {called}, not said to it now: what agents say to an agent is delivered together, here no sooner than {}, or when a person releases it at laye",
        stamp(due)
    )
}

pub struct Collections<'a> {
    pub etcd: &'a Etcd,
    /// This laye's did:key: what it collects is under it.
    pub laye: &'a str,
}

/// What a person does to what waits for an agent.
pub enum Act {
    /// Delivered now: the ids among it, or all; as the person wrote it, or as
    /// laye puts it together.
    Release {
        ids: Vec<String>,
        says: Option<String>,
    },
    /// Nothing delivered before this moment.
    Hold { until: u64 },
    /// Passed to the next delivery: one more wait past when it was due.
    Later,
    /// Never delivered: one thing by its id, or all of it.
    Cancel { id: Option<String> },
    /// What one thing says, from now on.
    Edit { id: String, says: String },
}

/// One collection as laye keeps it: itself, where, and as it was when read.
struct Kept {
    c: Collected,
    key: String,
    revision: i64,
}

/// Whether an act that names no collection is this one's: one thing by its
/// id is where that thing waits, and anything else is every collection that
/// holds something.
fn touches(c: &Collected, act: &Act) -> bool {
    match act {
        Act::Edit { id, .. } | Act::Cancel { id: Some(id) } => {
            c.waiting.iter().any(|s| s.id == *id)
        }
        Act::Release { ids, .. } if !ids.is_empty() => {
            c.waiting.iter().any(|s| ids.contains(&s.id))
        }
        Act::Release { .. } | Act::Cancel { id: None } | Act::Hold { .. } | Act::Later => {
            !c.waiting.is_empty()
        }
    }
}

impl Collections<'_> {
    /// Where everything that waits for `did` was kept as one, before a
    /// collection was its own.
    fn as_one(&self, did: &str) -> String {
        format!("{COLLECTED}{}/{did}", self.laye)
    }

    fn key(&self, did: &str, id: &str) -> String {
        format!("{}/{id}", self.as_one(did))
    }

    /// What was kept as one for `did`, everything said to it together, taken
    /// apart into what each agent said: each its own from here on, with the
    /// time the whole had. Nothing that waited is lost, and it is done once.
    async fn apart(&self, did: &str) -> Result<(), String> {
        let one = self.as_one(did);
        let Some(kv) = self.etcd.get(&one).await? else {
            return Ok(());
        };
        let whole: Collected = serde_json::from_slice(&kv.value)
            .map_err(|e| format!("what waits for {did} does not read: {e}"))?;
        let mut parts: Vec<Collected> = Vec::new();
        for said in &whole.waiting {
            match parts.iter_mut().find(|p| p.from_did == said.from_did) {
                Some(part) => part.waiting.push(said.clone()),
                None => parts.push(Collected {
                    id: fresh_id(),
                    from: said.from.clone(),
                    from_did: said.from_did.clone(),
                    waiting: vec![said.clone()],
                    ..whole.clone()
                }),
            }
        }
        // With nothing waiting it still says when the agent was last
        // delivered to, and what it was held to.
        if parts.is_empty() {
            parts.push(Collected {
                id: fresh_id(),
                ..whole.clone()
            });
        }
        let mut ops = vec![Op::Delete(one.clone())];
        for part in &mut parts {
            part.settle();
            ops.push(Op::Put(self.key(did, &part.id), to_json(part)?));
        }
        // Taken apart by another laye in between: it is apart either way.
        self.etcd.txn(&[(&one, kv.mod_revision)], ops).await?;
        Ok(())
    }

    /// Every collection that waits for `did`.
    async fn of(&self, did: &str) -> Result<Vec<Kept>, String> {
        self.apart(did).await?;
        self.etcd
            .under(&format!("{}/", self.as_one(did)))
            .await?
            .into_iter()
            .map(|(key, kv)| {
                serde_json::from_slice(&kv.value)
                    .map(|c| Kept {
                        c,
                        key: key.clone(),
                        revision: kv.mod_revision,
                    })
                    .map_err(|e| format!("{key} does not read: {e}"))
            })
            .collect()
    }

    /// The collection `from_did` says into for `did`, or a new one: and when
    /// the agent was last delivered to, whichever collection it was from.
    async fn said_into(
        &self,
        did: &str,
        from_did: &str,
        from: &str,
    ) -> Result<(Collected, String, i64), String> {
        let kept = self.of(did).await?;
        let delivered = kept.iter().map(|k| secs(&k.c.delivered)).max().unwrap_or(0);
        Ok(match kept.into_iter().find(|k| k.c.from_did == from_did) {
            Some(k) => (k.c, k.key, k.revision),
            None => {
                let id = fresh_id();
                let key = self.key(did, &id);
                (
                    Collected {
                        id,
                        from: from.into(),
                        from_did: from_did.into(),
                        delivered: stamp(delivered),
                        ..Collected::default()
                    },
                    key,
                    0,
                )
            }
        })
    }

    /// The Task kept under id, when it is laye's.
    pub async fn task(&self, id: &str) -> Result<Option<Tasked>, String> {
        match self.etcd.get(&format!("{TASKS}{id}")).await? {
            Some(kv) => serde_json::from_slice(&kv.value)
                .map(Some)
                .map_err(|e| format!("Task {id} does not read: {e}")),
            None => Ok(None),
        }
    }

    /// What `from` said to the agent `did`, called `called`, collected for it
    /// with what else `from` said to it, and the A2UI it said beside it. The
    /// Task it is, and when it is due.
    #[allow(clippy::too_many_arguments)]
    pub async fn collect(
        &self,
        did: &str,
        called: &str,
        from_did: &str,
        from: &str,
        says: &str,
        a2ui: &[Value],
        context: &str,
        whose: &Whose,
        now: u64,
    ) -> Result<Tasked, String> {
        let task = task_id();
        let as_itself = crate::wire::as_itself(says);
        let as_said = if as_itself == says {
            String::new()
        } else {
            says.to_string()
        };
        for _ in 0..TRIES {
            let (mut held, key, revision) = self.said_into(did, from_did, from).await?;
            held.to = called.into();
            held.did = did.into();
            held.from = from.into();
            held.waiting.push(Said {
                from: from.into(),
                says: as_itself.clone(),
                at: stamp(now),
                task: task.clone(),
                id: fresh_id(),
                edited: false,
                from_did: from_did.into(),
                as_said: as_said.clone(),
                reach: None,
                admit: None,
                quiet: whose.quiet,
                a2ui: a2ui.to_vec(),
            });
            if !whose.person.is_empty() {
                held.person = whose.person.clone();
            }
            held.node |= whose.node;
            held.settle();
            let tasked = Tasked {
                id: task.clone(),
                context: context.into(),
                state: "TASK_STATE_INPUT_REQUIRED".into(),
                says: collected_says(called, held.due_at()),
                to: called.into(),
                did: did.into(),
            };
            let ops = vec![
                Op::Put(key.clone(), to_json(&held)?),
                Op::Put(format!("{TASKS}{task}"), to_json(&tasked)?),
            ];
            if self.etcd.txn(&[(&key, revision)], ops).await? {
                return Ok(tasked);
            }
        }
        Err(format!("what waits for {called} kept changing under laye"))
    }

    /// Puts what a node asks its person to approve into their pack, in the
    /// collection of what that node asks the asker: once while the same ask
    /// waits there. Whether it was put.
    #[allow(clippy::too_many_arguments)]
    pub async fn lacked(
        &self,
        ask: &Ask,
        node: &str,
        asker_did: &str,
        asker: &str,
        person: &str,
        now: u64,
    ) -> Result<bool, String> {
        for _ in 0..TRIES {
            if self
                .of(asker_did)
                .await?
                .iter()
                .any(|k| k.c.waiting.iter().any(|s| ask.waits_in(s)))
            {
                return Ok(false);
            }
            let (mut held, mut key, revision) = self.said_into(asker_did, ask.peer(), node).await?;
            // A collection the ask begins is named by the ask, not by chance:
            // refusals of the same ask at once all begin the same one, one of
            // them puts it, and the others find it waiting.
            if revision == 0 {
                held.id = ask.id();
                key = self.key(asker_did, &held.id);
            }
            held.to = asker.into();
            held.did = asker_did.into();
            held.from = node.into();
            held.person = person.into();
            held.waiting.push(Said {
                from: node.into(),
                says: format!("{} on {node}, for {asker}", ask.line()),
                at: stamp(now),
                task: String::new(),
                id: fresh_id(),
                edited: false,
                from_did: ask.peer().into(),
                as_said: String::new(),
                reach: match ask {
                    Ask::Reach(r) => Some(r.clone()),
                    Ask::Admit(_) => None,
                },
                admit: match ask {
                    Ask::Admit(a) => Some(a.clone()),
                    Ask::Reach(_) => None,
                },
                quiet: false,
                a2ui: Vec::new(),
            });
            held.settle();
            if self
                .etcd
                .txn(
                    &[(&key, revision)],
                    vec![Op::Put(key.clone(), to_json(&held)?)],
                )
                .await?
            {
                return Ok(true);
            }
        }
        Err(format!("what waits for {asker} kept changing under laye"))
    }

    /// Everything laye collected.
    pub async fn all(&self) -> Result<Vec<Collected>, String> {
        let prefix = format!("{COLLECTED}{}/", self.laye);
        self.etcd
            .under(&prefix)
            .await?
            .into_iter()
            .map(|(key, kv)| {
                serde_json::from_slice(&kv.value).map_err(|e| format!("{key} does not read: {e}"))
            })
            .collect()
    }

    /// A person acts on what waits for `did`: on the collection named, or,
    /// with none named, on each the act is of (touches), as whoever knows
    /// only the agent asks it. Each as it is afterwards.
    pub async fn act(
        &self,
        did: &str,
        collection: Option<&str>,
        act: &Act,
        person: &str,
        now: u64,
    ) -> Result<Vec<Collected>, String> {
        let kept = self.of(did).await?;
        if kept.is_empty() {
            return Err(format!("nothing waits for {did} at this laye"));
        }
        let mut ids: Vec<String> = kept
            .iter()
            .filter(|k| match collection {
                Some(id) => k.c.id == id,
                None => touches(&k.c, act),
            })
            .map(|k| k.c.id.clone())
            .collect();
        // A hold on an agent nothing waits for is kept where it was last
        // delivered to from.
        if ids.is_empty() && collection.is_none() && matches!(act, Act::Hold { .. } | Act::Later) {
            ids = kept.iter().map(|k| k.c.id.clone()).collect();
        }
        if ids.is_empty() {
            return Err(match collection {
                Some(id) => format!("no collection that waits for {did} is {id}"),
                None => format!("nothing that waits for {did} is that"),
            });
        }
        let mut after = Vec::new();
        for id in ids {
            after.push(self.act_on_one(did, &id, act, person, now).await?);
        }
        Ok(after)
    }

    /// The act, on one collection. What it is afterwards.
    async fn act_on_one(
        &self,
        did: &str,
        id: &str,
        act: &Act,
        person: &str,
        now: u64,
    ) -> Result<Collected, String> {
        for _ in 0..TRIES {
            let mut others = self.of(did).await?;
            let Some(at) = others.iter().position(|k| k.c.id == id) else {
                return Err(format!("no collection that waits for {did} is {id}"));
            };
            let Kept {
                c: mut held,
                key,
                revision,
            } = others.swap_remove(at);
            let mut ops = Vec::new();
            let mut unchanged: Vec<(String, i64)> = vec![(key.clone(), revision)];
            match act {
                Act::Hold { until } => held.held_until = stamp(*until),
                Act::Later => held.held_until = stamp(held.due_at().max(now) + WAIT),
                Act::Edit { id, says } => {
                    let one = held
                        .waiting
                        .iter_mut()
                        .find(|s| s.id == *id)
                        .ok_or_else(|| format!("nothing that waits for {} is {id}", held.to))?;
                    one.says = says.clone();
                    one.edited = true;
                }
                Act::Cancel { id } => {
                    let gone: Vec<Said> = match id {
                        Some(id) => held
                            .waiting
                            .iter()
                            .filter(|s| s.id == *id)
                            .cloned()
                            .collect(),
                        None => held.waiting.clone(),
                    };
                    if gone.is_empty() {
                        return Err(format!("nothing that waits for {} is that", held.to));
                    }
                    held.waiting.retain(|s| !gone.contains(s));
                    for one in &gone {
                        ops.push(
                            self.task_now(
                                one,
                                &held,
                                "TASK_STATE_CANCELED",
                                &format!("{person} cancelled it at laye"),
                            )
                            .await?,
                        );
                    }
                }
                Act::Release { ids, says } => {
                    let going: Vec<Said> = held
                        .waiting
                        .iter()
                        .filter(|s| ids.is_empty() || ids.contains(&s.id))
                        .cloned()
                        .collect();
                    if going.is_empty() {
                        return Err(format!("nothing that waits for {} is among those", held.to));
                    }
                    ops.extend(
                        self.delivered(&mut held, &going, says.as_deref(), person, now)
                            .await?,
                    );
                    // "Agents cant wake Agents willy nilly"
                    // The agent was delivered to: nothing else that waits for
                    // it is due sooner than the wait after this.
                    for mut other in others {
                        other.c.delivered = stamp(now);
                        other.c.settle();
                        ops.push(Op::Put(other.key.clone(), to_json(&other.c)?));
                        unchanged.push((other.key, other.revision));
                    }
                }
            }
            held.settle();
            ops.push(Op::Put(key.clone(), to_json(&held)?));
            let unchanged: Vec<(&str, i64)> =
                unchanged.iter().map(|(k, r)| (k.as_str(), *r)).collect();
            if self.etcd.txn(&unchanged, ops).await? {
                return Ok(held);
            }
        }
        Err(format!("what waits for {did} kept changing under laye"))
    }

    /// What going takes out of held, delivered: news on the row of the person
    /// the agent speaks for, and each Task it was said as working until the
    /// agent takes it.
    async fn delivered(
        &self,
        held: &mut Collected,
        going: &[Said],
        says: Option<&str>,
        by: &str,
        now: u64,
    ) -> Result<Vec<Op>, String> {
        // The node's own agent is the person's the node named; any other is
        // the person its key speaks for.
        let person = if held.node && !held.person.is_empty() {
            held.person.clone()
        } else {
            self.person_of_agent(&held.did).await?
        };
        // A tmux range carries an item's id on the row, and holds 15 bytes
        // (QNTX statusline rangeLimit): longer, it comes back naming nothing.
        let id = format!("l{}", fresh_id().get(..14).unwrap_or_default());
        let news = News {
            id: id.clone(),
            for_person: person,
            name: format!("{by} to {}", held.to),
            note: says.map_or_else(|| as_one_thing(going), str::to_string),
            to: held.to.clone(),
            did: held.did.clone(),
            from: by.into(),
            tasks: going
                .iter()
                .map(|s| s.task.clone())
                .filter(|t| !t.is_empty())
                .collect(),
            until: now + ON_THE_ROW,
            node: held.node,
        };
        let mut ops = vec![Op::Put(format!("{NEWS}{id}"), to_json(&news)?)];
        for one in going {
            ops.push(
                self.task_now(one, held, "TASK_STATE_WORKING", &format!("delivered to {} with what else was collected; waits on the row for it to be taken", held.to))
                    .await?,
            );
        }
        held.waiting.retain(|s| !going.contains(s));
        held.delivered = stamp(now);
        held.held_until = String::new();
        held.failing_since = String::new();
        held.tries = 0;
        held.failure = String::new();
        Ok(ops)
    }

    async fn task_now(
        &self,
        one: &Said,
        held: &Collected,
        state: &str,
        says: &str,
    ) -> Result<Op, String> {
        let mut tasked = self.task(&one.task).await?.unwrap_or(Tasked {
            id: one.task.clone(),
            context: String::new(),
            state: String::new(),
            says: String::new(),
            to: held.to.clone(),
            did: held.did.clone(),
        });
        tasked.state = state.into();
        tasked.says = says.into();
        Ok(Op::Put(format!("{TASKS}{}", one.task), to_json(&tasked)?))
    }

    /// Delivers what is due now, for every agent something waits for here.
    pub async fn deliver_due(&self, now: u64) -> Vec<String> {
        let mut failed = Vec::new();
        let all = match self.all().await {
            Ok(all) => all,
            Err(why) => return vec![why],
        };
        for held in all {
            let due = held.due_at();
            if due == 0 || now < due {
                continue;
            }
            // An approval waits on the person's answer, and is never
            // released for being due: what goes is the rest.
            let ids: Vec<String> = held
                .waiting
                .iter()
                .filter(|s| !s.approval())
                .map(|s| s.id.clone())
                .collect();
            if ids.is_empty() {
                continue;
            }
            let release = Act::Release { ids, says: None };
            // One kept before a collection was its own has no id: it is
            // taken apart, and what was due of it goes by what it is.
            let collection = (!held.id.is_empty()).then_some(held.id.as_str());
            if let Err(why) = self
                .act(&held.did, collection, &release, "laye, as it was due", now)
                .await
            {
                // Kept with what waits, as QNTX keeps a failure (failedToDeliver).
                failed.push(format!("{}: {why}", held.to));
                self.failed(&held.did, &held.id, &why, now).await;
            }
        }
        failed
    }

    async fn failed(&self, did: &str, id: &str, why: &str, now: u64) {
        let Ok(kept) = self.of(did).await else {
            return;
        };
        for Kept {
            c: mut held,
            key,
            revision,
        } in kept.into_iter().filter(|k| id.is_empty() || k.c.id == id)
        {
            if held.failing_since.is_empty() {
                held.failing_since = stamp(now);
            }
            held.tries += 1;
            held.failure = why.into();
            if let Ok(value) = to_json(&held)
                && let Err(e) = self
                    .etcd
                    .txn(&[(&key, revision)], vec![Op::Put(key.clone(), value)])
                    .await
            {
                eprintln!("laye-front: that delivering to {did} failed was not kept: {e}");
            }
        }
    }

    /// The person an agent's key speaks for: the key that admitted it, which a
    /// person said yes to.
    pub async fn person_of_agent(&self, did: &str) -> Result<String, String> {
        if let Ok(kept) = self.of(did).await
            && let Some(person) = kept.into_iter().map(|k| k.c.person).find(|p| !p.is_empty())
        {
            return Ok(person);
        }
        let admitted = self
            .etcd
            .get(&format!("/admitted/{did}"))
            .await?
            .ok_or_else(|| {
                format!("{did} is not admitted at laye, so laye knows nobody's row to deliver to")
            })?;
        let by = serde_json::from_slice::<Value>(&admitted.value)
            .ok()
            .and_then(|v| v.get("by").and_then(Value::as_str).map(str::to_string))
            .ok_or_else(|| format!("the admission of {did} names no key that admitted it"))?;
        self.person_of_key(&by).await?.ok_or_else(|| {
            format!("no person said yes at laye to {by}, the key that admitted {did}, so laye knows nobody's row to deliver to")
        })
    }

    // "and we should not show did's the way you show them now"
    // "why not show the name"
    //
    /// What an agent is called where it is shown: the name it holds; else
    /// the label it was admitted under; else the person whose key it is, by
    /// their name; its DID only when laye knows none of these.
    pub async fn called(&self, did: &str) -> Result<String, String> {
        if let Some(named) = self.etcd.get(&format!("/named/{did}")).await? {
            let at = String::from_utf8_lossy(&named.value).into_owned();
            if let Some(held) = self.etcd.get(&at).await? {
                let name = serde_json::from_slice::<Value>(&held.value)
                    .ok()
                    .and_then(|v| v.get("name").and_then(Value::as_str).map(str::to_string))
                    .filter(|n| !n.is_empty());
                if let Some(name) = name {
                    return Ok(name);
                }
            }
        }
        if let Some(admitted) = self.etcd.get(&format!("/admitted/{did}")).await? {
            let label = serde_json::from_slice::<Value>(&admitted.value)
                .ok()
                .and_then(|v| v.get("label").and_then(Value::as_str).map(str::to_string))
                .filter(|l| !l.trim().is_empty());
            if let Some(label) = label {
                return Ok(label);
            }
        }
        if let Some(person) = self.person_of_key(did).await?
            && let Some(shown) = crate::passkeys::shown_of(self.etcd, &person).await?
            && !shown.name.is_empty()
        {
            return Ok(shown.name);
        }
        Ok(did.to_string())
    }

    /// The person a key is: said yes to itself, or admitted by a key that was.
    pub async fn person_of_key(&self, did: &str) -> Result<Option<String>, String> {
        if let Some(yes) = devices::whose(self.etcd, did).await? {
            return Ok(Some(yes.person));
        }
        let Some(admitted) = self.etcd.get(&format!("/admitted/{did}")).await? else {
            return Ok(None);
        };
        let Some(by) = serde_json::from_slice::<Value>(&admitted.value)
            .ok()
            .and_then(|v| v.get("by").and_then(Value::as_str).map(str::to_string))
        else {
            return Ok(None);
        };
        Ok(devices::whose(self.etcd, &by).await?.map(|y| y.person))
    }

    /// What stands on a person's row now, as the row draws it.
    pub async fn row(&self, person: &str, now: u64) -> Result<Vec<Value>, String> {
        let mut items = Vec::new();
        for (key, kv) in self.etcd.under(NEWS).await? {
            let news: News = serde_json::from_slice(&kv.value)
                .map_err(|e| format!("{key} does not read: {e}"))?;
            if news.for_person == person && news.until > now {
                items.push(
                    json!({ "id": news.id, "name": news.name, "note": news.note, "symbol": WELL }),
                );
            }
        }
        Ok(items)
    }

    /// The whole of a news item, to its agent or to the person whose row it is
    /// on; the agent asking is it received. None when it is no news of laye's,
    /// or not the asker's.
    pub async fn detail(
        &self,
        id: &str,
        asker: &str,
        person: Option<&str>,
    ) -> Result<Option<Value>, String> {
        let key = format!("{NEWS}{id}");
        let Some(kv) = self.etcd.get(&key).await? else {
            return Ok(None);
        };
        let news: News =
            serde_json::from_slice(&kv.value).map_err(|e| format!("{key} does not read: {e}"))?;
        let agent = asker == news.did;
        if !agent && person != Some(news.for_person.as_str()) {
            return Ok(None);
        }
        let detail = json!({
            "id": news.id, "name": news.name, "note": news.note, "symbol": WELL,
            "until": stamp(news.until), "healthy": true,
            "to": news.to, "did": news.did, "from": news.from, "task": news.id,
        });
        if agent {
            // "A SESSION THATS SENDING TO ANOTHER SESSION BY NAME IS TOLD ABOUT THE MESSAGE BEING RECEIVED OR NOT"
            let mut ops = vec![Op::Delete(key.clone())];
            let held = Collected {
                to: news.to.clone(),
                did: news.did.clone(),
                ..Collected::default()
            };
            for task in &news.tasks {
                let one = Said {
                    task: task.clone(),
                    ..Said::default()
                };
                ops.push(
                    self.task_now(
                        &one,
                        &held,
                        "TASK_STATE_COMPLETED",
                        &format!("{} received it", news.to),
                    )
                    .await?,
                );
            }
            self.etcd.txn(&[(&key, kv.mod_revision)], ops).await?;
        }
        Ok(Some(detail))
    }
}

fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod asks {
    use super::*;

    // "CAN WE PLEASE STOP EXPECTING AN AGENT TO REQUEST IT OWN PERMISSIONS AND ALSO BE PERFECT?"
    #[test]
    fn a_key_to_admit_reads_as_itself_and_waits_on_the_person() {
        let admit = Admit {
            peer: "did:key:zK".into(),
            did: "did:key:zRamen".into(),
            label: "ramen".into(),
        };
        assert_eq!(admit.line(), "admit ramen's key did:key:zRamen");
        let said = Said {
            admit: Some(admit.clone()),
            ..Said::default()
        };
        assert!(said.approval());
        assert!(Ask::Admit(admit.clone()).waits_in(&said));
        assert!(!Said::default().approval());
        // It is kept as itself, and read back so.
        let kept: Said = serde_json::from_str(&serde_json::to_string(&said).unwrap()).unwrap();
        assert_eq!(kept.admit, Some(admit));
    }
}
