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

/// 「[Opus 5.5] What `waits` names a person's one activity by: everything that waits on them.」
pub const ON: &str = "laye/waits-on/";

/// 「[Opus 5.5] The `waits` of the one activity of `person`.」
pub fn waits_on(person: &str) -> String {
    format!("{ON}{person}")
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
    /// 「[Opus 5.5] When the app handed it, in seconds since 1970.」
    #[serde(default)]
    pub since: u64,
}

/// "Apple is saying max 8 hours per activity, we dont care, we keep it going
/// 「[Opus 5.5] by cancelling beofre it ends and starting again."」
///
/// 「[Opus 5.5] How long one activity stands before laye starts the next for the same」
/// 「[Opus 5.5] person on the same phone, short of Apple's eight hours. The one before」
/// 「[Opus 5.5] ends once the next stands, so what waits is there the whole time.」
pub const RENEW: u64 = 7 * 3600;

/// 「[Opus 5.5] Whether an activity that stood since `since` is to be followed by the next.」
pub fn renewed(since: u64, now: u64) -> bool {
    now.saturating_sub(since) >= RENEW
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
pub async fn keep(
    held: &Collections<'_>,
    person: &str,
    handed: &Handed,
    now: u64,
) -> Result<(), String> {
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
                since: now,
            };
            Op::Put(key, serde_json::to_vec(&stands).map_err(|e| e.to_string())?)
        }
    };
    held.etcd.txn(&[], vec![op]).await.map(|_| ())
}

/// 「[Opus 5.5] What was said, as one line: its words, cut at `at_most` characters.」
fn line(said: &str, at_most: usize) -> String {
    let said: String = said.split_whitespace().collect::<Vec<_>>().join(" ");
    let cut: String = said.chars().take(at_most).collect();
    if cut.chars().count() < said.chars().count() {
        format!("{cut}…")
    } else {
        cut
    }
}

/// 「[Opus 5.5] What goes out next of what waits on a person: the one due first. One that」
/// 「[Opus 5.5] is due at no time goes after every one that is.」
pub fn lead<'a>(waiting: &[&'a Collected]) -> Option<&'a Collected> {
    waiting
        .iter()
        .copied()
        .filter(|c| !c.waiting.is_empty())
        .min_by_key(|c| match crate::collected::secs(&c.due) {
            0 => u64::MAX,
            due => due,
        })
}

/// "One activity, for you, holding everything that waits on you."
///
/// 「[Opus 5.5] What a person's one activity shows: what goes out next, as it was said;」
/// 「[Opus 5.5] what waits after it, a line each, as many as are drawn and how many more;」
/// 「[Opus 5.5] and the presses, on what goes out next.」
pub fn shown(waiting: &[&Collected]) -> Option<serde_json::Value> {
    let lead = lead(waiting)?;
    let mut after: Vec<&Collected> = waiting
        .iter()
        .copied()
        .filter(|c| !c.waiting.is_empty() && c.named() != lead.named())
        .collect();
    after.sort_by_key(|c| match crate::collected::secs(&c.due) {
        0 => u64::MAX,
        due => due,
    });
    let mut said = lead
        .waiting
        .iter()
        .chain(after.iter().flat_map(|c| c.waiting.iter()));
    let says = line(&said.next()?.says, 160);
    let rest: Vec<String> = said.map(|one| line(&one.says, 90)).collect();
    // 「[Opus 5.5] The lock screen draws four lines of it.」
    let lines: Vec<String> = if rest.len() <= 4 {
        rest
    } else {
        let more = rest.len() - 3;
        rest.into_iter()
            .take(3)
            .chain(std::iter::once(format!("and {more} more")))
            .collect()
    };
    let press = |says: &str, does: &str, then: &str, act: &str, armed: bool| {
        serde_json::json!({
            "says": says, "does": does, "then": then, "path": format!("{ACT}{act}"),
            "sent": { "to": lead.did, "collection": lead.id }, "armed": armed,
        })
    };
    // "SESSION CANT REACH, IT NEEDS REACH LINE(S), IT GETS IN FRONT OF MY VIA AG OR LIVE ACTIVITY AS SOMETHING TO APPROVE,"
    // 「[Opus 5.5] What goes out next is approvals alone: approve or deny, the thing itself.」
    if lead.waiting.iter().all(|s| s.approval()) {
        return Some(serde_json::json!({
            "says": says,
            "preview": lines.join("\n"),
            "due": 0.0,
            "segments": [],
            "presses": [
                press("approve", "approve", "approved", "release", false),
                press("deny", "cancel", "denied", "cancel", true),
            ],
        }));
    }
    Some(serde_json::json!({
        "says": says,
        "preview": lines.join("\n"),
        "due": crate::collected::secs(&lead.due) as f64,
        "segments": [],
        "presses": [
            press("send now", "approve", "sent", "release", false),
            press("delay", "delay", "delayed", "later", false),
            press("cancel", "cancel", "canceled", "cancel", true),
        ],
    }))
}

/// A mark of what one shows, so it is said again only when it changed.
pub fn mark(shown: &serde_json::Value) -> String {
    let sum = Sha256::digest(shown.to_string().as_bytes());
    sum.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Makes what stands on each phone what waits at laye now: started where it
/// does not stand, moved where it changed, ended where nothing waits.
/// Every failure is said.
/// "they are all me."
///
/// Whose phones what waits stands on: every root's, as a ROOT sees whatever
/// waits (lib.rs, theirs), and the person it waits on.
pub fn people_shown(roots: &[String], person: Option<String>) -> Vec<String> {
    let mut people = roots.to_vec();
    if let Some(person) = person
        && !people.contains(&person)
    {
        people.push(person);
    }
    people
}

/// `roots` are laye's root identities: a ROOT sees whatever waits, in ag as
/// here (lib.rs, theirs), so what waits stands on every root's phone too.
pub async fn show(held: &Collections<'_>, apns: &Apns, roots: &[String], now: u64) -> Vec<String> {
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

    // 「[Opus 5.5] Everything that waits on each person.」
    let mut on: Vec<(String, Vec<&Collected>)> = Vec::new();
    for c in all.iter().filter(|c| !c.waiting.is_empty()) {
        for person in people_shown(roots, held.person_of_agent(&c.did).await.ok()) {
            match on.iter_mut().find(|(p, _)| *p == person) {
                Some((_, waiting)) => waiting.push(c),
                None => on.push((person, vec![c])),
            }
        }
    }

    // 「[Opus 5.5] Started on each of a person's phones where something waits on them and」
    // 「[Opus 5.5] their one activity does not stand.」
    for (person, waiting) in &on {
        let Some(state) = shown(waiting) else {
            continue;
        };
        let phones = match held.etcd.under(&format!("{PHONES}{person}/")).await {
            Ok(kvs) => kvs,
            Err(why) => {
                failed.push(why);
                continue;
            }
        };
        let waits = waits_on(person);
        for (key, _) in phones {
            let Some(phone) = key.rsplit('/').next().map(str::to_string) else {
                continue;
            };
            if stands
                .iter()
                .any(|(_, s)| s.waits == waits && s.phone == phone && !renewed(s.since, now))
            {
                continue;
            }
            // 「[Opus 5.5] Started once, until the app hands back the activity's own token,」
            // 「[Opus 5.5] or until it is the next one's time.」
            let started = format!("{STARTED}{phone}/{person}");
            if let Ok(Some(kv)) = held.etcd.get(&started).await
                && let Ok(at) = String::from_utf8_lossy(&kv.value).parse::<u64>()
                && !renewed(at, now)
            {
                continue;
            }
            let text = |field: &str| {
                state
                    .get(field)
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string()
            };
            let said = Said {
                token: phone.clone(),
                event: "start",
                state: state.clone(),
                attributes: Some((
                    TYPE,
                    serde_json::json!({ "waits": waits, "kind": "collected", "title": "" }),
                )),
                alert: Some((text("says"), text("preview"))),
                stale: 0,
                dismissal: 0,
            };
            match apns.say(&said).await {
                Ok(_) => {
                    if let Err(why) = held
                        .etcd
                        .txn(&[], vec![Op::Put(started, now.to_string().into_bytes())])
                        .await
                    {
                        failed.push(why);
                    }
                    eprintln!("laye-front: what waits on {person} stands on a phone of theirs");
                }
                Err(Ok(refused)) if refused.gone() => {
                    if let Err(why) = held.etcd.txn(&[], vec![Op::Delete(key)]).await {
                        failed.push(why);
                    }
                }
                Err(Ok(refused)) => {
                    failed.push(format!("starting what waits on {person}: {refused}"))
                }
                Err(Err(why)) => failed.push(format!("starting what waits on {person}: {why}")),
            }
        }
    }

    // 「[Opus 5.5] Moved where it changed, ended where nothing waits on its person. One」
    // 「[Opus 5.5] that stands for a single collection, as laye started them before, ends.」
    let all_stands: Vec<(String, u64, String)> = stands
        .iter()
        .map(|(_, s)| (s.waits.clone(), s.since, s.phone.clone()))
        .collect();
    for (token, mut stands) in stands {
        // 「[Opus 5.5] The next one stands on the same phone: this one is followed, and ends now.」
        let followed = renewed(stands.since, now)
            && all_stands.iter().any(|(waits, since, phone)| {
                *waits == stands.waits && *phone == stands.phone && *since > stands.since
            });
        let now_shown = (!followed)
            .then_some(())
            .and_then(|()| stands.waits.strip_prefix(ON))
            .and_then(|person| {
                on.iter()
                    .find(|(p, _)| p == person)
                    .and_then(|(_, waiting)| shown(waiting))
            });
        let (event, state, stale, dismissal) = match now_shown {
            Some(state) => {
                if mark(&state) == stands.shows {
                    continue;
                }
                ("update", state, 0, 0)
            }
            None => (
                "end",
                serde_json::json!({ "says": "nothing waits", "preview": "", "due": 0.0, "segments": [], "presses": [] }),
                0,
                if followed { now } else { now + 60 },
            ),
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

    fn waiting(id: &str, due: &str, says: &[&str]) -> Collected {
        Collected {
            id: id.into(),
            to: "Cumulus".into(),
            did: "did:key:zCumulus".into(),
            due: due.into(),
            waiting: says
                .iter()
                .map(|says| Spoken {
                    from: "Fuck".into(),
                    says: (*says).into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    // "One activity, for you, holding everything that waits on you."
    #[test]
    fn everything_that_waits_on_a_person_is_one_activity() {
        let later = waiting("b", "2026-11-28T10:00:00Z", &["goes out later"]);
        let next = waiting("a", "2026-11-28T09:00:00Z", &["goes out next"]);
        let state = shown(&[&later, &next]).unwrap();
        assert_eq!(state["says"], "goes out next");
        assert_eq!(state["preview"], "goes out later");
    }

    #[test]
    fn what_is_said_is_shown_without_who_or_how_many() {
        let one = waiting("a", "2026-11-28T09:00:00Z", &["Fuck here, about laye"]);
        let state = shown(&[&one]).unwrap();
        assert_eq!(state["says"], "Fuck here, about laye");
        assert_eq!(state["preview"], "");
    }

    #[test]
    fn a_press_acts_on_what_goes_out_next() {
        let later = waiting("b", "2026-11-28T10:00:00Z", &["later"]);
        let next = waiting("a", "2026-11-28T09:00:00Z", &["next"]);
        let state = shown(&[&later, &next]).unwrap();
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
        assert!(presses.iter().all(|p| p["sent"]["collection"] == "a"));
        assert!(
            presses
                .iter()
                .all(|p| p["sent"]["to"] == "did:key:zCumulus")
        );
        assert_eq!(state["due"], secs_of("2026-11-28T09:00:00Z"));
    }

    fn secs_of(at: &str) -> f64 {
        crate::collected::secs(at) as f64
    }

    #[test]
    fn what_is_due_at_no_time_goes_after_what_is() {
        let never = waiting("b", "", &["quiet"]);
        let due = waiting("a", "2026-11-28T09:00:00Z", &["due"]);
        assert_eq!(lead(&[&never, &due]).unwrap().id, "a");
    }

    #[test]
    fn nothing_waiting_shows_nothing() {
        assert!(shown(&[]).is_none());
        assert!(shown(&[&waiting("a", "", &[])]).is_none());
    }

    #[test]
    fn what_a_refusal_lacked_is_approved_or_denied_on_the_island() {
        let mut c = waiting("a", "", &["reach"]);
        c.waiting[0].reach = Some(crate::collected::Reach {
            peer: "did:key:zK".into(),
            path: "lines:scene".into(),
            to: "TOKEN".into(),
        });
        let state = shown(&[&c]).unwrap();
        let presses = state["presses"].as_array().unwrap();
        let said: Vec<_> = presses
            .iter()
            .map(|p| p["says"].as_str().unwrap())
            .collect();
        assert_eq!(said, ["approve", "deny"]);
        assert_eq!(presses[0]["path"], "/api/laye/collected/release");
        assert_eq!(presses[1]["path"], "/api/laye/collected/cancel");
    }

    // "CAN WE PLEASE STOP EXPECTING AN AGENT TO REQUEST IT OWN PERMISSIONS AND ALSO BE PERFECT?"
    #[test]
    fn a_key_to_admit_is_approved_or_denied_on_the_island() {
        let mut c = waiting("a", "", &["admit"]);
        c.waiting[0].admit = Some(crate::collected::Admit {
            peer: "did:key:zK".into(),
            did: "did:key:zRamen".into(),
            label: "ramen".into(),
        });
        let state = shown(&[&c]).unwrap();
        let said: Vec<_> = state["presses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["says"].as_str().unwrap())
            .collect();
        assert_eq!(said, ["approve", "deny"]);
    }

    // "they are all me."
    #[test]
    fn what_waits_stands_on_every_roots_phone_and_its_persons() {
        let roots = vec!["github:1739143".to_string(), "google:1101".to_string()];
        assert_eq!(people_shown(&roots, Some("github:1739143".into())), roots);
        assert_eq!(
            people_shown(&roots, Some("a person a root invited".into())),
            ["github:1739143", "google:1101", "a person a root invited"]
        );
        assert_eq!(people_shown(&roots, None), roots);
    }

    #[test]
    fn past_four_lines_after_it_is_said_as_how_many_more() {
        let c = waiting("a", "2026-11-28T09:00:00Z", &["0", "1", "2", "3", "4", "5"]);
        let state = shown(&[&c]).unwrap();
        assert_eq!(state["says"], "0");
        assert_eq!(state["preview"], "1\n2\n3\nand 2 more");
        let four = waiting("a", "2026-11-28T09:00:00Z", &["0", "1", "2", "3", "4"]);
        assert_eq!(shown(&[&four]).unwrap()["preview"], "1\n2\n3\n4");
    }

    #[test]
    fn what_changed_is_marked_otherwise() {
        let one = waiting("a", "", &["0"]);
        let two = waiting("a", "", &["0", "1"]);
        assert_ne!(
            mark(&shown(&[&one]).unwrap()),
            mark(&shown(&[&two]).unwrap())
        );
        assert_eq!(
            mark(&shown(&[&two]).unwrap()),
            mark(&shown(&[&two]).unwrap())
        );
    }

    // "if a collection is pending wake for multiple days, i expect the activity to be there the whole fucking time."
    #[test]
    fn the_next_activity_is_started_before_apples_eight_hours() {
        assert!(!renewed(1_000, 1_000 + RENEW - 1));
        assert!(renewed(1_000, 1_000 + RENEW));
        const { assert!(RENEW < 8 * 3600) };
    }

    #[test]
    fn a_persons_activity_is_named_by_them() {
        assert_eq!(waits_on("github:1739143"), "laye/waits-on/github:1739143");
    }

    #[test]
    fn a_token_is_apples_in_hex() {
        assert!(a_token(&"ab".repeat(32)));
        assert!(!a_token("short"));
        assert!(!a_token(&"AB".repeat(32)));
        assert!(!a_token(&format!("{}/../x", "ab".repeat(32))));
    }
}
