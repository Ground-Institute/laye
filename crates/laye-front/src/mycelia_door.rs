//! The door mycelia holds the person's session through, as QNTX's way home
//! from a door (server/auth/homeward.go), at laye.

// "it needs to move to laye anyways"
// "ag's presses go to laye, through a laye door for mycelia."
// "kept. kept bro, i want to put my finger on, and then not have to thing about it anymore"
//
// 「[Opus 5.5] mycelia sends the person to /laye/door/home, the passkey is done」
// 「[Opus 5.5] on laye's page, and laye sends the browser back to mycelia's door」
// 「[Opus 5.5] with a ticket, which buys the door's session once. That session is」
// 「[Opus 5.5] the person's for what is collected alone: /laye/collected and what」
// 「[Opus 5.5] is done with it. A passkey session it is not, so it says yes to no」
// 「[Opus 5.5] key and reaches nothing else at laye.」

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use laye_me::Keypair;

use crate::jwt;

/// The doors laye sends a person back to: mycelia's, as QNTX's am.toml names
/// it in `auth.rp_origins`.
pub const DOORS: [&str; 1] = ["mycelia://door"];

/// The cookie holding a journey's ticket while the passkey is done.
pub const COOKIE: &str = "laye_door";

/// Whom a door's session is for, which no passkey session is.
pub const AUD: &str = "laye-door";

/// How long a door's session lasts: as long as the node's door session
/// (`session_expiry_hours = 168` in q's and l's am.toml).
pub const LIFE: u64 = 168 * 3600;

/// How long a journey waits for the passkey, and a held session for its door:
/// ten minutes, as QNTX's homewardTTL.
pub const JOURNEY: u64 = 600;

struct Held {
    door: String,
    token: String,
    person: String,
    until: u64,
    at: u64,
}

/// The journeys open and the sessions held for their doors, by ticket.
#[derive(Default)]
pub struct Journeys {
    open: Mutex<HashMap<String, (String, u64)>>,
    held: Mutex<HashMap<String, Held>>,
}

/// What a door collects: the session, whose it is, and until when.
pub struct Collected {
    pub token: String,
    pub person: String,
    pub until: u64,
}

impl Journeys {
    /// A journey home from `door`: the ticket the browser carries.
    pub fn open(&self, door: &str, now: u64) -> Result<String, String> {
        if !DOORS.contains(&door) {
            return Err(format!("laye sends nobody back to {door:?}"));
        }
        let ticket = B64URL.encode(rand::random::<[u8; 32]>());
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        open.retain(|_, (_, at)| now.saturating_sub(*at) <= JOURNEY);
        open.insert(ticket.clone(), (door.to_string(), now));
        Ok(ticket)
    }

    /// The person signed in on the journey `ticket`: a session for its door is
    /// held, and where the browser goes back to is answered.
    pub fn send(
        &self,
        ticket: &str,
        person: &str,
        level: &str,
        laye: &str,
        key: &Keypair,
        now: u64,
    ) -> Result<String, (u16, String)> {
        let opened = self
            .open
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(ticket);
        let Some((door, _)) = opened.filter(|(_, at)| now.saturating_sub(*at) <= JOURNEY) else {
            return Err((
                404,
                "no journey from a door is open for this browser".into(),
            ));
        };
        let until = now + LIFE;
        let token = jwt::sign(
            key,
            &jwt::Claims {
                iss: laye.to_string(),
                sub: person.to_string(),
                aud: vec![AUD.into()],
                exp: until,
                iat: now,
                jti: jwt::fresh_jti(),
                label: level.to_string(),
            },
        )
        .map_err(|e| (500, format!("the door's session was not signed: {e}")))?;
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        held.retain(|_, h| now.saturating_sub(h.at) <= JOURNEY);
        held.insert(
            ticket.to_string(),
            Held {
                door: door.clone(),
                token,
                person: person.to_string(),
                until,
                at: now,
            },
        );
        Ok(format!("{door}?home={ticket}"))
    }

    /// The door collecting its session, once: only the door the journey began at.
    pub fn collect(&self, ticket: &str, door: &str, now: u64) -> Result<Collected, (u16, String)> {
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        let fresh = held
            .get(ticket)
            .is_some_and(|h| now.saturating_sub(h.at) <= JOURNEY);
        if !fresh {
            held.remove(ticket);
            return Err((404, "no session is held for this ticket".into()));
        }
        if held.get(ticket).is_some_and(|h| h.door != door) {
            return Err((401, format!("this ticket's session is not {door:?}'s")));
        }
        let Some(h) = held.remove(ticket) else {
            return Err((404, "no session is held for this ticket".into()));
        };
        Ok(Collected {
            token: h.token,
            person: h.person,
            until: h.until,
        })
    }
}

/// The person a door's session is, at this laye, and their level.
pub fn person_of(token: &str, laye: &str, now: u64) -> Result<(String, String), String> {
    let claims =
        jwt::read(token).map_err(|e| format!("the door's session does not verify: {e}"))?;
    if claims.iss != laye {
        return Err(format!(
            "the door's session is {}'s, and this laye is {laye}",
            claims.iss
        ));
    }
    if !claims.aud.iter().any(|a| a == AUD) {
        return Err("the token is no door's session".into());
    }
    if claims.exp <= now {
        return Err("the door's session is over".into());
    }
    Ok((claims.sub, claims.label))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn laye() -> (Keypair, String) {
        let key = Keypair::generate_ed25519();
        let did = laye_peer::did_of(&key).unwrap_or_default();
        (key, did)
    }

    #[test]
    fn a_door_collects_the_session_once_and_it_opens_what_is_collected_alone() {
        let (key, did) = laye();
        let journeys = Journeys::default();
        let ticket = journeys.open("mycelia://door", 100).unwrap_or_default();
        let to = journeys
            .send(&ticket, "did:key:zPerson", "ROOT", &did, &key, 160)
            .unwrap_or_default();
        assert_eq!(to, format!("mycelia://door?home={ticket}"));

        let got = journeys.collect(&ticket, "mycelia://door", 170);
        assert!(got.is_ok(), "the door did not collect its session");
        let Ok(got) = got else { return };
        assert_eq!(got.person, "did:key:zPerson");
        assert_eq!(got.until, 160 + LIFE);
        assert_eq!(
            person_of(&got.token, &did, 160 + LIFE - 1),
            Ok(("did:key:zPerson".to_string(), "ROOT".to_string()))
        );
        assert!(
            person_of(&got.token, &did, 160 + LIFE).is_err(),
            "a door's session ends"
        );
        assert!(
            crate::passkeys::person_of(&got.token, &did, 170).is_err(),
            "a door's session is no passkey session"
        );
        assert!(
            journeys.collect(&ticket, "mycelia://door", 171).is_err(),
            "a ticket is spent once"
        );
    }

    #[test]
    fn laye_sends_nobody_to_a_door_it_does_not_know_nor_late() {
        let (key, did) = laye();
        let journeys = Journeys::default();
        assert!(journeys.open("https://elsewhere.example", 0).is_err());

        let ticket = journeys.open("mycelia://door", 0).unwrap_or_default();
        assert!(
            journeys
                .send(&ticket, "did:key:zPerson", "USER", &did, &key, JOURNEY + 1)
                .is_err(),
            "a journey waits ten minutes"
        );

        let ticket = journeys.open("mycelia://door", 0).unwrap_or_default();
        let sent = journeys.send(&ticket, "did:key:zPerson", "USER", &did, &key, 10);
        assert!(sent.is_ok());
        assert!(
            journeys.collect(&ticket, "mycelia://other", 20).is_err(),
            "only the journey's own door collects"
        );
        assert!(
            journeys
                .collect(&ticket, "mycelia://door", 20 + JOURNEY + 1)
                .is_err(),
            "a held session waits ten minutes"
        );
    }
}
