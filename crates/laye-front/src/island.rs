//! "laye should get it's own island as well"
//! "laye owning collections, with the island in laye."
//!
//! What waits at laye for a person's agents stands on the island of laye's own
//! app, on their phone: started by laye through Apple with the app closed,
//! moved as what waits changes, and ended when nothing waits. A press on it
//! is the person's act on the collection, at laye.
//!
//! The app hands laye the tokens Apple gives it: the phone's, to start one by,
//! and each activity's own, to move and end it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::apns::{Apns, Said};
use crate::collected::{Collected, Collections};
use crate::etcd::Op;

/// The tokens a person's phones start Live Activities by: `/island/phones/<person>/<token>`.
pub const PHONES: &str = "/island/phones/";
/// Each activity that stands, by its own token: `/island/stands/<token>`.
pub const STANDS: &str = "/island/stands/";
/// The time a collection was last started for on a phone: `/island/started/<phone>/<did>`.
pub const STARTED: &str = "/island/started/";

/// The one Live Activity type of laye's app.
pub const TYPE: &str = "WaitsAttributes";

/// Where a press on the island acts, under /api/ as every island's press asks
/// (lib.rs, /api/laye/collected/<act>).
pub const ACT: &str = "/api/laye/collected/";

/// What `waits` names a collection by.
pub fn waits_of(did: &str) -> String {
    format!("laye/collected/{did}")
}

/// One activity that stands on a phone, as laye last said it.
#[derive(Serialize, Deserialize, Default)]
pub struct Stands {
    pub person: String,
    pub waits: String,
    /// The phone it stands on, by the token it starts them by.
    #[serde(default)]
    pub phone: String,
    /// What it shows, marked, as laye last said it.
    #[serde(default)]
    pub shows: String,
}

/// What the app hands laye: a phone's token, or an activity's own with what it is of.
#[derive(Deserialize)]
pub struct Handed {
    pub token: String,
    #[serde(default)]
    pub waits: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub gone: bool,
}

/// Whether a token is one as the app reads it off the system, in hex.
pub fn a_token(said: &str) -> bool {
    (32..=512).contains(&said.len())
        && said
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Keeps what the app handed for `person`.
pub async fn keep(held: &Collections<'_>, person: &str, handed: &Handed) -> Result<(), String> {
    let token = handed.token.trim().to_ascii_lowercase();
    if !a_token(&token) {
        return Err("token is a token Apple gave, in hex".into());
    }
    let op = if handed.waits.is_empty() {
        let key = format!("{PHONES}{person}/{token}");
        if handed.gone {
            Op::Delete(key)
        } else {
            Op::Put(key, b"{}".to_vec())
        }
    } else {
        let key = format!("{STANDS}{token}");
        if handed.gone {
            Op::Delete(key)
        } else {
            let stands = Stands {
                person: person.into(),
                waits: handed.waits.clone(),
                phone: handed.phone.trim().to_ascii_lowercase(),
                shows: String::new(),
            };
            Op::Put(key, serde_json::to_vec(&stands).map_err(|e| e.to_string())?)
        }
    };
    held.etcd.txn(&[], vec![op]).await.map(|_| ())
}

/// What one shows of a collection: how many wait, the first few, when it
/// goes, and the three presses.
pub fn shown(c: &Collected) -> serde_json::Value {
    let n = c.waiting.len();
    let says = if n == 1 {
        "1 waits".to_string()
    } else {
        format!("{n} wait")
    };
    let mut lines: Vec<String> = Vec::new();
    for one in &c.waiting {
        let said: String = one.says.split_whitespace().collect::<Vec<_>>().join(" ");
        let cut: String = said.chars().take(90).collect();
        let cut = if cut.len() < said.len() {
            format!("{cut}…")
        } else {
            cut
        };
        let from: String = one.from.chars().take(40).collect();
        lines.push(format!("{from}: {cut}"));
        if lines.len() == 4 && n > 4 {
            lines.push(format!("and {} more", n - 4));
            break;
        }
    }
    let press = |says: &str, does: &str, then: &str, act: &str, armed: bool| {
        serde_json::json!({
            "says": says, "does": does, "then": then, "path": format!("{ACT}{act}"),
            "sent": { "to": c.did }, "armed": armed,
        })
    };
    serde_json::json!({
        "says": says,
        "preview": lines.join("\n"),
        "due": crate::collected::secs(&c.due) as f64,
        "segments": [],
        "presses": [
            press("send now", "approve", "sent", "release", false),
            press("delay", "delay", "delayed", "later", false),
            press("cancel", "cancel", "canceled", "cancel", true),
        ],
    })
}

/// A mark of what one shows, so it is said again only when it changed.
pub fn mark(shown: &serde_json::Value) -> String {
    let sum = Sha256::digest(shown.to_string().as_bytes());
    sum.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Makes what stands on each phone what waits at laye now: started where it
/// does not stand, moved where it changed, ended where nothing waits.
/// Every failure is said.
pub async fn show(held: &Collections<'_>, apns: &Apns, now: u64) -> Vec<String> {
    let mut failed = Vec::new();
    let all = match held.all().await {
        Ok(all) => all,
        Err(why) => return vec![why],
    };
    let stands: Vec<(String, Stands)> = match held.etcd.under(STANDS).await {
        Ok(kvs) => kvs
            .into_iter()
            .filter_map(|(key, kv)| {
                let token = key.strip_prefix(STANDS)?.to_string();
                Some((token, serde_json::from_slice(&kv.value).ok()?))
            })
            .collect(),
        Err(why) => return vec![why],
    };

    // Started where it waits and does not stand.
    for c in all.iter().filter(|c| !c.waiting.is_empty()) {
        let person = match held.person_of_agent(&c.did).await {
            Ok(person) => person,
            Err(_) => continue,
        };
        let phones = match held.etcd.under(&format!("{PHONES}{person}/")).await {
            Ok(kvs) => kvs,
            Err(why) => {
                failed.push(why);
                continue;
            }
        };
        let waits = waits_of(&c.did);
        for (key, _) in phones {
            let Some(phone) = key.rsplit('/').next().map(str::to_string) else {
                continue;
            };
            if stands
                .iter()
                .any(|(_, s)| s.waits == waits && s.phone == phone)
            {
                continue;
            }
            let started = format!("{STARTED}{phone}/{}", c.did);
            if let Ok(Some(kv)) = held.etcd.get(&started).await
                && kv.value == c.due.as_bytes()
            {
                continue;
            }
            let state = shown(c);
            let alert = (
                format!(
                    "{} for {}",
                    state
                        .get("says")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default(),
                    c.to
                ),
                state
                    .get("preview")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            );
            let due = crate::collected::secs(&c.due);
            let said = Said {
                token: phone.clone(),
                event: "start",
                state,
                attributes: Some((
                    TYPE,
                    serde_json::json!({ "waits": waits, "kind": "collected", "title": format!("for {}", c.to) }),
                )),
                alert: Some(alert),
                stale: due,
                dismissal: 0,
            };
            match apns.say(&said).await {
                Ok(_) => {
                    if let Err(why) = held
                        .etcd
                        .txn(&[], vec![Op::Put(started, c.due.as_bytes().to_vec())])
                        .await
                    {
                        failed.push(why);
                    }
                    eprintln!(
                        "laye-front: what waits for {} stands on a phone of {person}",
                        c.to
                    );
                }
                Err(Ok(refused)) if refused.gone() => {
                    if let Err(why) = held.etcd.txn(&[], vec![Op::Delete(key)]).await {
                        failed.push(why);
                    }
                }
                Err(Ok(refused)) => {
                    failed.push(format!("starting what waits for {}: {refused}", c.to))
                }
                Err(Err(why)) => failed.push(format!("starting what waits for {}: {why}", c.to)),
            }
        }
    }

    // Moved where it changed, ended where nothing waits.
    for (token, mut stands) in stands {
        let Some(did) = stands.waits.strip_prefix("laye/collected/") else {
            continue;
        };
        let c = all.iter().find(|c| c.did == did);
        let (event, state, stale, dismissal) = match c {
            Some(c) if !c.waiting.is_empty() => {
                let state = shown(c);
                if mark(&state) == stands.shows {
                    continue;
                }
                ("update", state, crate::collected::secs(&c.due), 0)
            }
            _ => {
                let became = match c {
                    Some(c)
                        if !c.delivered.is_empty()
                            && now.saturating_sub(crate::collected::secs(&c.delivered)) < 3600 =>
                    {
                        "sent"
                    }
                    _ => "canceled",
                };
                (
                    "end",
                    serde_json::json!({ "says": became, "preview": "", "due": 0.0, "segments": [], "presses": [] }),
                    0,
                    now + 60,
                )
            }
        };
        let said = Said {
            token: token.clone(),
            event,
            state: state.clone(),
            attributes: None,
            alert: None,
            stale,
            dismissal,
        };
        let key = format!("{STANDS}{token}");
        match apns.say(&said).await {
            Ok(_) if event == "end" => {
                if let Err(why) = held.etcd.txn(&[], vec![Op::Delete(key)]).await {
                    failed.push(why);
                }
            }
            Ok(_) => {
                stands.shows = mark(&state);
                match serde_json::to_vec(&stands) {
                    Ok(v) => {
                        if let Err(why) = held.etcd.txn(&[], vec![Op::Put(key, v)]).await {
                            failed.push(why);
                        }
                    }
                    Err(e) => failed.push(e.to_string()),
                }
            }
            Err(Ok(refused)) if refused.gone() => {
                if let Err(why) = held.etcd.txn(&[], vec![Op::Delete(key)]).await {
                    failed.push(why);
                }
            }
            Err(Ok(refused)) => {
                failed.push(format!("saying {event} to {}: {refused}", stands.waits))
            }
            Err(Err(why)) => failed.push(format!("saying {event} to {}: {why}", stands.waits)),
        }
    }
    failed
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::collected::Said as Spoken;

    fn waiting(n: usize) -> Collected {
        Collected {
            to: "Cumulus".into(),
            did: "did:key:zCumulus".into(),
            due: "2026-11-23T01:22:50Z".into(),
            waiting: (0..n)
                .map(|i| Spoken {
                    from: "ChatGPT".into(),
                    says: format!("said {i}"),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_press_on_the_island_is_the_persons_act_on_that_collection() {
        let state = shown(&waiting(1));
        assert_eq!(state["says"], "1 waits");
        assert_eq!(state["preview"], "ChatGPT: said 0");
        let presses = state["presses"].as_array().unwrap();
        let paths: Vec<_> = presses
            .iter()
            .map(|p| p["path"].as_str().unwrap())
            .collect();
        assert_eq!(
            paths,
            [
                "/api/laye/collected/release",
                "/api/laye/collected/later",
                "/api/laye/collected/cancel"
            ]
        );
        assert!(
            presses
                .iter()
                .all(|p| p["sent"]["to"] == "did:key:zCumulus")
        );
    }

    #[test]
    fn more_than_four_are_said_as_how_many_more() {
        let state = shown(&waiting(6));
        assert_eq!(state["says"], "6 wait");
        assert!(state["preview"].as_str().unwrap().ends_with("and 2 more"));
    }

    #[test]
    fn what_changed_is_marked_otherwise() {
        assert_ne!(mark(&shown(&waiting(1))), mark(&shown(&waiting(2))));
        assert_eq!(mark(&shown(&waiting(2))), mark(&shown(&waiting(2))));
    }

    #[test]
    fn a_token_is_apples_in_hex() {
        assert!(a_token(&"ab".repeat(32)));
        assert!(!a_token("short"));
        assert!(!a_token(&"AB".repeat(32)));
        assert!(!a_token(&format!("{}/../x", "ab".repeat(32))));
    }
}
