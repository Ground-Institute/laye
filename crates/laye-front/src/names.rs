//! Who is admitted, and the name each session holds: laye's, kept in etcd, so
//! every laye sharing that etcd gives one name to one session.

// "I WANT A SESSION TO BE ABLE TO GIVE ITSELF AN AVAILABLE NAME, AMONGST ALL PARTICIPANTS IN THE CLUSTER"
// "SO, ONE ALDER"
// "ONE SLATE"
// "AND LAYE OWNS IDENTITY"
// "I'd put names under /names/ there from the start,"
//
// A session's key is admitted by a key laye's settings name, and then the
// session names itself by its own key. A name is one session's at a time, in
// any case of its letters; a session that takes another name lets go of the
// one it held. QNTX is told of each, as it was told before laye answered them.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::etcd::{Etcd, Op};

/// Where a session's admission is kept: `/admitted/<did>`.
const ADMITTED: &str = "/admitted/";
/// Where a name is kept, by its letters in lower case: `/names/<name>`.
const NAMES: &str = "/names/";
/// Where the name a session holds is found from its DID: `/named/<did>`.
const NAMED: &str = "/named/";

/// How often a name is asked for again when another laye wrote between.
const TRIES: usize = 5;

/// As QNTX holds a name to: `auth.MaxName`.
const MAX_NAME: usize = 64;
/// As QNTX holds it: root is nobody's name (`access.RootName`).
const ROOT_NAME: &str = "root";
/// Who gives a session its name, as QNTX takes it (`nameGivers`).
const GIVERS: [&str; 3] = ["user", "itself", "harness"];

pub struct Names {
    pub etcd: Etcd,
    /// The keys whose signature admits a session's key: the key the person
    /// said yes to, ~/.qntx/key, on each machine.
    pub admitters: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Admitted {
    label: String,
    by: String,
    at: u64,
}

#[derive(Serialize, Deserialize)]
struct Held {
    name: String,
    did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    given: Option<String>,
    at: u64,
}

/// What laye answers: a status and its words.
pub type Answer = (u16, String);

impl Names {
    /// `signer` admits `did`, called `label`. 200 admitted now; 409 already.
    pub async fn admit(&self, signer: &str, did: &str, label: &str, now: u64) -> Answer {
        // A key laye's settings name, or a key a person said yes to at laye.
        let said_yes_to = match crate::devices::whose(&self.etcd, signer).await {
            Ok(yes) => yes.is_some(),
            Err(e) => return (503, e),
        };
        if !said_yes_to && !self.admitters.iter().any(|a| a == signer) {
            return (
                403,
                format!("{signer} is not a key laye takes to admit a session's key"),
            );
        }
        if let Err(e) = laye_me::didkey::decode(did) {
            return (400, format!("did is no did:key: {e}"));
        }
        if did == signer {
            return (400, "a key does not admit itself".into());
        }
        let label = label.trim();
        if label.is_empty() {
            return (
                400,
                "label is what the session is called, and is required".into(),
            );
        }
        let key = format!("{ADMITTED}{did}");
        let record = match serde_json::to_vec(&Admitted {
            label: label.into(),
            by: signer.into(),
            at: now,
        }) {
            Ok(record) => record,
            Err(e) => return (500, e.to_string()),
        };
        // Written only where nothing is kept yet: the first admission stands.
        match self
            .etcd
            .txn(&[(&key, 0)], vec![Op::Put(key.clone(), record)])
            .await
        {
            Ok(true) => (
                200,
                json!({ "did": did, "admitted_by": signer }).to_string(),
            ),
            Ok(false) => (409, format!("{did} is already held")),
            Err(e) => (503, e),
        }
    }

    /// The session `did` takes `name`. 200 with the name and the DID; 403 when
    /// another session holds it.
    pub async fn name(&self, did: &str, name: &str, given: Option<&str>, now: u64) -> Answer {
        let name = name.trim();
        if let Some(why) = no_name(name) {
            return (400, why);
        }
        if let Some(given) = given.filter(|g| !g.is_empty())
            && !GIVERS.contains(&given)
        {
            return (
                400,
                format!("{given:?} is not who gives a name: {}", GIVERS.join(", ")),
            );
        }
        match self.etcd.get(&format!("{ADMITTED}{did}")).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return (
                    401,
                    format!(
                        "{did} is not admitted at laye: a key laye takes admits it first, at /auth/admit"
                    ),
                );
            }
            Err(e) => return (503, e),
        }
        let at = format!("{NAMES}{}", name.to_ascii_lowercase());
        let mine = format!("{NAMED}{did}");
        for _ in 0..TRIES {
            let held = match self.etcd.get(&at).await {
                Ok(held) => held,
                Err(e) => return (503, e),
            };
            let holder = match held
                .as_ref()
                .map(|kv| serde_json::from_slice::<Held>(&kv.value))
                .transpose()
            {
                Ok(holder) => holder,
                Err(e) => return (500, format!("what is kept at {at} does not read: {e}")),
            };
            if let Some(holder) = &holder {
                if holder.did != did {
                    return (
                        403,
                        format!(
                            "{name:?} is taken: another agent holds it. Ask again with another name."
                        ),
                    );
                }
                if holder.name == name {
                    return (200, named(name, did));
                }
            }
            let left = match self.etcd.get(&mine).await {
                Ok(left) => left,
                Err(e) => return (503, e),
            };
            let record = match serde_json::to_vec(&Held {
                name: name.into(),
                did: did.into(),
                given: given.filter(|g| !g.is_empty()).map(str::to_string),
                at: now,
            }) {
                Ok(record) => record,
                Err(e) => return (500, e.to_string()),
            };
            let mut ops = vec![
                Op::Put(at.clone(), record),
                Op::Put(mine.clone(), at.clone().into_bytes()),
            ];
            let mut unchanged = vec![
                (at.as_str(), held.as_ref().map_or(0, |kv| kv.mod_revision)),
                (mine.as_str(), left.as_ref().map_or(0, |kv| kv.mod_revision)),
            ];
            // The name it held is let go of, while it is still this session's.
            let was = left
                .as_ref()
                .and_then(|kv| String::from_utf8(kv.value.clone()).ok())
                .filter(|was| *was != at);
            let was_held = match &was {
                Some(was) => match self.etcd.get(was).await {
                    Ok(kv) => kv,
                    Err(e) => return (503, e),
                },
                None => None,
            };
            if let (Some(was), Some(kv)) = (&was, &was_held)
                && serde_json::from_slice::<Held>(&kv.value).is_ok_and(|h| h.did == did)
            {
                ops.push(Op::Delete(was.clone()));
                unchanged.push((was.as_str(), kv.mod_revision));
            }
            match self.etcd.txn(&unchanged, ops).await {
                Ok(true) => return (200, named(name, did)),
                // Another laye wrote between the reading and the writing.
                Ok(false) => continue,
                Err(e) => return (503, e),
            }
        }
        (
            503,
            format!(
                "{name:?} was asked for by others as often as this asked {TRIES} times; ask again"
            ),
        )
    }
}

/// What QNTX answers a name with (`protocol.Named`).
fn named(name: &str, did: &str) -> String {
    json!({ "name": name, "did": did }).to_string()
}

/// Why this is no name, as QNTX says it (`noName`); None when it is one.
pub fn no_name(name: &str) -> Option<String> {
    if name.is_empty() || name.chars().any(char::is_control) {
        return Some("a name is one line of text".into());
    }
    if name.len() > MAX_NAME {
        return Some(format!("the name is longer than {MAX_NAME} characters"));
    }
    if name.eq_ignore_ascii_case(ROOT_NAME) {
        return Some(format!("{ROOT_NAME} is not available"));
    }
    // "i want to ban numbers in names"
    // "a name is an Uppercase character followed by normal lowercase characters"
    // "and a name can be two names after each other as well"
    // "or three"
    // "so no special chars in names as well"
    // "a Name needs to be able to be phonetically spoken"
    // "Names need to be compatible with STT/TTS"
    let words: Vec<&str> = name.split(' ').collect();
    if words.len() > 3 {
        return Some("a name is one, two or three words".into());
    }
    for word in words {
        if !can_be_said(word) {
            return Some(format!(
                "a name is one, two or three words, each a capital letter and then lowercase letters, with a vowel to say it by: {word:?} is not one"
            ));
        }
    }
    None
}

/// A capital letter and then lowercase letters, a to z, one of them a vowel.
fn can_be_said(word: &str) -> bool {
    let mut letters = word.chars();
    let Some(first) = letters.next() else {
        return false;
    };
    if word.len() < 2 || !first.is_ascii_uppercase() {
        return false;
    }
    let mut voiced = "AEIOUY".contains(first);
    for letter in letters {
        if !letter.is_ascii_lowercase() {
            return false;
        }
        voiced = voiced || "aeiouy".contains(letter);
    }
    voiced
}

#[cfg(test)]
mod tests {
    use super::no_name;

    #[test]
    fn a_name_is_what_qntx_holds_a_name_to() {
        for name in ["Alder", "Slate", "Mary Ann", "Ya Ya Ya", "Ab"] {
            assert_eq!(no_name(name), None, "{name}");
        }
        for name in [
            "",
            "alder",
            "Alder2",
            "AL",
            "Brr",
            "Al-der",
            "A b",
            "Root",
            "ROOT",
            "One Two Three Four",
            "Al\nder",
        ] {
            assert!(no_name(name).is_some(), "{name:?} is a name");
        }
    }
}
