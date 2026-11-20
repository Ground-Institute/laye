//! What an agent says to an agent, collected by laye: kept in etcd for the
//! agent it was said to, delivered together when it is due or when a person
//! releases it, and received when that agent asks for it.

// "i want laye to also be tht A2A layer collections get placed into and be added or removed from and be released."
// "Agents cant wake Agents willy nilly"
// "the messages collect"
// "and as a human i can dial it"
// "and as a human i can observe it"
//
// Kept as QNTX keeps it (server/collected.go): one key for each agent, under
// /collected/<laye's DID>/, in the shape `collected list` answers, so mycelia,
// `ground collected` and ag read laye's as they read a node's. A delivery is
// news on the row of the person the agent's key speaks for; it is received
// when the agent itself asks for the whole of it. Only a person's passkey
// session holds, releases, passes on, cancels or edits.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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
}

/// What waits for one agent, as `collected list` says it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Collected {
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
    /// When what waits is delivered if nobody holds or releases it, as QNTX's
    /// `due`: the wait after the first of it, no sooner than the wait after the
    /// last delivery, and no sooner than a person held it to.
    fn due_at(&self) -> u64 {
        let Some(first) = self.waiting.first() else {
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

impl Collections<'_> {
    fn key(&self, did: &str) -> String {
        format!("{COLLECTED}{}/{did}", self.laye)
    }

    async fn read(&self, did: &str) -> Result<(Collected, i64), String> {
        match self.etcd.get(&self.key(did)).await? {
            Some(kv) => serde_json::from_slice(&kv.value)
                .map(|c| (c, kv.mod_revision))
                .map_err(|e| format!("what waits for {did} does not read: {e}")),
            None => Ok((Collected::default(), 0)),
        }
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

    /// What `from` said to the agent `did`, called `called`, collected for it.
    /// The Task it is, and when it is due.
    #[allow(clippy::too_many_arguments)]
    pub async fn collect(
        &self,
        did: &str,
        called: &str,
        from_did: &str,
        from: &str,
        says: &str,
        context: &str,
        now: u64,
    ) -> Result<Tasked, String> {
        let task = task_id();
        for _ in 0..TRIES {
            let (mut held, revision) = self.read(did).await?;
            held.to = called.into();
            held.did = did.into();
            held.waiting.push(Said {
                from: from.into(),
                says: says.into(),
                at: stamp(now),
                task: task.clone(),
                id: fresh_id(),
                edited: false,
                from_did: from_did.into(),
            });
            held.settle();
            let tasked = Tasked {
                id: task.clone(),
                context: context.into(),
                state: "TASK_STATE_INPUT_REQUIRED".into(),
                says: collected_says(called, held.due_at()),
                to: called.into(),
                did: did.into(),
            };
            let key = self.key(did);
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

    /// A person acts on what waits for `did`. What waits for it afterwards.
    pub async fn act(
        &self,
        did: &str,
        act: &Act,
        person: &str,
        now: u64,
    ) -> Result<Collected, String> {
        for _ in 0..TRIES {
            let (mut held, revision) = self.read(did).await?;
            if revision == 0 {
                return Err(format!("nothing waits for {did} at this laye"));
            }
            let mut ops = Vec::new();
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
                }
            }
            held.settle();
            let key = self.key(did);
            ops.push(Op::Put(key.clone(), to_json(&held)?));
            if self.etcd.txn(&[(&key, revision)], ops).await? {
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
        let person = self.person_of_agent(&held.did).await?;
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
            let release = Act::Release {
                ids: Vec::new(),
                says: None,
            };
            if let Err(why) = self
                .act(&held.did, &release, "laye, as it was due", now)
                .await
            {
                // Kept with what waits, as QNTX keeps a failure (failedToDeliver).
                failed.push(format!("{}: {why}", held.to));
                self.failed(&held.did, &why, now).await;
            }
        }
        failed
    }

    async fn failed(&self, did: &str, why: &str, now: u64) {
        if let Ok((mut held, revision)) = self.read(did).await
            && revision > 0
        {
            if held.failing_since.is_empty() {
                held.failing_since = stamp(now);
            }
            held.tries += 1;
            held.failure = why.into();
            let key = self.key(did);
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
