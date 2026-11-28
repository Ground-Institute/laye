//! laye in front of QNTX.
//!
//! Every request reaches laye first. A session's own signature is checked
//! here, and QNTX is told by laye whose request it is: laye owns identity.
//! Who that is as a User stays QNTX's to say. What a session says while QNTX
//! is down is kept, and handed over when QNTX is back.

// "LAYE IN FRONT OF QNTX"
// "QNTX CAN GO DOWN"
// "WHILE LAYE IS STILL THERE"
// "AND LAYE OWNS IDENTITY"
// "BUT LAYE DOES NOT REALLY OWN USER, THE QNTX WAY"

pub mod a2a_card;
pub mod a2a_spoken;
pub mod a2ui;
pub mod apns;
pub mod collected;
mod connectors;
pub mod devices;
pub mod door;
pub mod etcd;
pub mod invitations;
pub mod island;
mod issuer;
pub mod jwt;
mod mail;
pub mod mycelia_door;
pub mod names;
pub mod passkeys;
pub mod watched;
pub mod wire;

pub use issuer::Node;

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use laye_me::Keypair;
use sacred_error::Error;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// The scheme a signed request carries, as QNTX reads it.
const SIGNED: &str = "Signed ";

/// How long a session's signature may last, as QNTX allows (assertionMaxLife).
const MAX_LIFE: u64 = 300;

/// How long laye's own signature for one carried request lasts, as QNTX's
/// primary signs (carriedLife).
const CARRIED_LIFE: u64 = 60;

/// How often laye tries to hand over what it kept while QNTX was down.
const RETRY: Duration = Duration::from_secs(1);

pub struct Config {
    /// Where laye takes requests: what Caddy hands them to.
    pub listen: SocketAddr,
    /// QNTX behind laye, as an origin: http://127.0.0.1:8770.
    pub qntx: String,
    /// QNTX's own did:key: what laye's signature is for.
    pub qntx_did: String,
    /// The origins sessions sign for: https://laye.ground.institute, and
    /// whatever else hands requests to laye.
    pub public_origins: Vec<String>,
    /// Where what was said while QNTX was down is kept.
    pub held_at: PathBuf,
    /// Who administers the network: a did:key, or an account a trusted
    /// signer bound to a key. Nobody else logs in through laye.
    pub root_identities: Vec<String>,
    /// Whose signature on a binding counts, as hex ed25519 keys.
    pub binding_signers: Vec<String>,
    /// laye's own origin, where people log in: https://laye.ground.institute.
    pub issuer: String,
    /// The nodes whose people log in at laye.
    pub nodes: Vec<Node>,
    /// Where the invitations a root made are kept.
    pub invitations_at: PathBuf,
    /// Where an account proves itself, for laye's login screen: the origin
    /// of the provider ceremony, https://api.q.sbvh.nl.
    pub ceremony_at: String,
    /// Where laye keeps who is admitted and the names sessions hold. None
    /// leaves both to QNTX.
    pub names: Option<NamesAt>,
    /// laye's passkeys, kept in the etcd names are. None makes none.
    pub passkeys: Option<passkeys::PasskeysAt>,
    /// Where laye's wasm is, for laye's own page: laye-web. None is beside
    /// the binary, at ../share/laye/web.
    pub web: Option<PathBuf>,
    /// Apple, for laye's own island. None starts nothing on a phone.
    pub apns: Option<apns::ApnsAt>,
    /// The nodes, beside QNTX in front of which laye stands, that hand laye
    /// the reach a refused request lacked, by their did:key.
    pub pack_nodes: Vec<String>,
    /// What ground's pbt says of this laye. None says it was given nothing.
    pub governed: Option<Governed>,
}

/// Where names are kept, and whose key admits a session's.
#[derive(Clone, Debug, Deserialize)]
pub struct NamesAt {
    /// etcd, as its clients reach it: http://127.0.0.1:2379.
    pub etcd: String,
    /// The did:keys whose signature admits a session's key.
    pub admitters: Vec<String>,
    // "names and collections and just smaller things, messages say's status"
    /// The etcd user laye asks as, whose role reaches only what laye keeps.
    /// None asks as nobody, as etcd without authentication is asked.
    #[serde(default)]
    pub etcd_user: Option<String>,
    /// The file holding that user's password.
    #[serde(default)]
    pub etcd_password_file: Option<PathBuf>,
}

impl NamesAt {
    /// etcd as laye asks it: as `etcd_user`, when one is named.
    fn etcd(
        &self,
        client: Client<HttpConnector, Full<Bytes>>,
    ) -> Result<etcd::Etcd, Box<sacred_error::Error>> {
        let Some(user) = &self.etcd_user else {
            return Ok(etcd::Etcd::new(&self.etcd, client));
        };
        let Some(file) = &self.etcd_password_file else {
            return Err(laye_peer::error(
                "names",
                "laye is told to ask etcd as a user, and not where its password is",
                format!("[names] etcd_user = {user:?} names no etcd_password_file"),
            ));
        };
        let password = std::fs::read_to_string(file).map_err(|e| {
            laye_peer::error(
                "names",
                "the password laye asks etcd with was not read",
                format!("{}: {e}", file.display()),
            )
        })?;
        Ok(etcd::Etcd::new(&self.etcd, client).as_user(user, password.trim()))
    }
}

pub struct Front {
    pub addr: SocketAddr,
    pub did: String,
}

/// A request kept while QNTX did not answer, as it will be handed over.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Held {
    path: String,
    headers: Vec<(String, String)>,
    body: String,
    /// The session that signed it.
    subject: String,
}

struct Inner {
    config: Config,
    key: Keypair,
    did: String,
    client: Client<HttpConnector, Full<Bytes>>,
    /// QNTX over HTTP/2 without TLS, for what arrived in HTTP/2: gRPC.
    h2c: Client<HttpConnector, Full<Bytes>>,
    /// Signatures presented, by id, until they expire: each is spent once.
    seen: Mutex<HashMap<String, u64>>,
    held: Mutex<Vec<Held>>,
    issued: issuer::Issued,
    invitations: invitations::Invitations,
    names: Option<names::Names>,
    passkeys: Option<passkeys::Passkeys>,
    web: Option<PathBuf>,
    /// Journeys home from mycelia's door, and the sessions held for it.
    journeys: mycelia_door::Journeys,
    /// laye's sender to Apple, for its island.
    apns: Option<apns::Apns>,
}

/// laye, listening in front of QNTX. The handle runs it; abort it to stop.
pub async fn start(config: Config, key: Keypair) -> Result<(Front, JoinHandle<()>), Box<Error>> {
    let did = laye_peer::did_of(&key)
        .ok_or_else(|| laye_peer::error("key", "laye's key is not an ed25519 key", ""))?;
    let held = load(&config.held_at)?;
    let invited = invitations::Invitations::load(&config.invitations_at).map_err(|why| {
        laye_peer::error("invitations", "the invitations laye keeps do not read", why)
    })?;
    let listener = TcpListener::bind(config.listen).await.map_err(|e| {
        laye_peer::error(
            "listen",
            "laye does not listen",
            format!("{}: {e}", config.listen),
        )
    })?;
    let addr = listener
        .local_addr()
        .map_err(|e| laye_peer::error("listen", "laye's address is not known", e.to_string()))?;
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let names = match config.names.as_ref() {
        Some(at) => Some(names::Names {
            etcd: at.etcd(client.clone())?,
            admitters: at.admitters.clone(),
        }),
        None => None,
    };
    let passkeys = match (&config.passkeys, &config.names) {
        (Some(at), Some(names)) => Some(passkeys::Passkeys::new(
            names.etcd(client.clone())?,
            at.clone(),
        )),
        (Some(_), None) => {
            return Err(laye_peer::error(
                "passkeys",
                "laye keeps passkeys in the etcd it keeps names in, and names none",
                "",
            ));
        }
        _ => None,
    };
    let web = config.web.clone().or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|exe| Some(exe.parent()?.parent()?.join("share/laye/web")))
    });
    let apns = match config.apns.clone() {
        Some(at) => Some(
            apns::Apns::new(at)
                .map_err(|why| laye_peer::error("apns", "laye does not reach Apple", why))?,
        ),
        None => None,
    };
    let inner = Arc::new(Inner {
        apns,
        passkeys,
        web,
        config,
        key,
        did: did.clone(),
        client,
        names,
        h2c: Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build_http(),
        seen: Mutex::new(HashMap::new()),
        held: Mutex::new(held),
        issued: issuer::Issued::default(),
        invitations: invited,
        journeys: mycelia_door::Journeys::default(),
    });
    let run = tokio::spawn(async move {
        let mut tick = tokio::time::interval(RETRY);
        let mut ticks: u64 = 0;
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let inner = inner.clone();
                    tokio::spawn(async move {
                        let service = hyper::service::service_fn(move |req| {
                            let inner = inner.clone();
                            async move { Ok::<_, Infallible>(answer(&inner, req).await) }
                        });
                        // HTTP/1, and HTTP/2 without TLS: gRPC is HTTP/2, and
                        // arrives from the front door that ended TLS without it,
                        // as QNTX takes it (server/lifecycle.go).
                        if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                            .serve_connection_with_upgrades(TokioIo::new(stream), service)
                            .await
                        {
                            eprintln!("laye-front: a connection ended: {e}");
                        }
                    });
                }
                _ = tick.tick() => {
                    hand_over(&inner).await;
                    ticks += 1;
                    // What was released for QNTX's own agent goes to QNTX.
                    if ticks.is_multiple_of(5) && let Some(keys) = &inner.passkeys {
                        for why in hand_to_node(&inner, &keys.etcd).await {
                            eprintln!("laye-front: what was released for QNTX's agent was not handed to QNTX: {why}");
                        }
                    }
                    // "laye should get it's own island as well"
                    if ticks.is_multiple_of(15) && let (Some(keys), Some(apns)) = (&inner.passkeys, &inner.apns) {
                        let held = collected::Collections { etcd: &keys.etcd, laye: &inner.did };
                        for why in island::show(&held, apns, &inner.config.root_identities, now()).await {
                            eprintln!("laye-front: what waits was not shown on the island as it stands: {why}");
                        }
                    }
                    if ticks.is_multiple_of(60) && let Some(keys) = &inner.passkeys {
                        let held = collected::Collections { etcd: &keys.etcd, laye: &inner.did };
                        for why in held.deliver_due(now()).await {
                            eprintln!("laye-front: what was collected and due was not delivered: {why}");
                        }
                        for why in connectors::sweep(&keys.etcd, now()).await {
                            eprintln!("laye-front: a connector's ended code or token was not swept: {why}");
                        }
                    }
                }
            }
        }
    });
    Ok((Front { addr, did }, run))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn laye_of(inner: &Inner) -> issuer::Laye<'_> {
    issuer::Laye {
        issuer: &inner.config.issuer,
        did: &inner.did,
        nodes: &inner.config.nodes,
        roots: &inner.config.root_identities,
        signers: &inner.config.binding_signers,
        issued: &inner.issued,
        invitations: &inner.invitations,
        ceremony: &inner.config.ceremony_at,
        now: now(),
    }
}

fn host_of(parts: &hyper::http::request::Parts) -> &str {
    parts
        .headers
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
}

fn named_by(origin: &str, host: &str) -> bool {
    origin
        .split_once("://")
        .is_some_and(|(_, name)| name.trim_end_matches('/') == host)
}

/// The person a request's session cookie is, at this laye.
fn person_asking(
    inner: &Inner,
    parts: &hyper::http::request::Parts,
) -> Result<(String, String), String> {
    session_asking(inner, parts).map(|(person, level, _)| (person, level))
}

/// The person a request's session cookie is, their level, and until when.
fn session_asking(
    inner: &Inner,
    parts: &hyper::http::request::Parts,
) -> Result<(String, String, u64), String> {
    let token = parts
        .headers
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| {
            c.trim()
                .strip_prefix(passkeys::SESSION_COOKIE)
                .and_then(|rest| rest.strip_prefix('='))
        })
        .ok_or("no person's session is presented")?;
    passkeys::person_of(token, &inner.did, now())
}

/// A cookie the request carries, by name.
fn cookie_of<'a>(parts: &'a hyper::http::request::Parts, name: &str) -> Option<&'a str> {
    parts
        .headers
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(name)?.strip_prefix('='))
}

/// The person what is collected is shown to and acted on for: their passkey
/// session, or the session mycelia's door collected for them.
fn collecting_for(
    inner: &Inner,
    parts: &hyper::http::request::Parts,
) -> Result<(String, String), String> {
    let bearer = parts
        .headers
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    // A bearer is mycelia's door ticket, or the session laye's app holds and
    // its island presents (APP_SESSION).
    match bearer {
        Some(token) => mycelia_door::person_of(token.trim(), &inner.did, now()).or_else(|door| {
            passkeys::person_of(token.trim(), &inner.did, now())
                .map(|(person, level, _)| (person, level))
                .map_err(|session| format!("{door}; {session}"))
        }),
        None => person_asking(inner, parts),
    }
}

fn door_cookie(ticket: Option<&str>) -> String {
    match ticket {
        Some(ticket) => format!(
            "{}={ticket}; Path=/laye; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
            mycelia_door::COOKIE,
            mycelia_door::JOURNEY
        ),
        None => format!(
            "{}=; Path=/laye; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
            mycelia_door::COOKIE
        ),
    }
}

fn session_cookie(token: Option<&str>) -> String {
    match token {
        Some(token) => format!(
            "{}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
            passkeys::SESSION_COOKIE,
            passkeys::SESSION_LIFE
        ),
        None => format!(
            "{}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
            passkeys::SESSION_COOKIE
        ),
    }
}

/// laye's page for a person, and what it asks: their passkeys and their
/// session, at laye's own name and at every origin its passkeys answer at.
async fn as_person(
    inner: &Inner,
    parts: &hyper::http::request::Parts,
    body: &[u8],
) -> Option<Response<Body>> {
    let keys = inner.passkeys.as_ref()?;
    let host = host_of(parts);
    let ours =
        named_by(&inner.config.issuer, host) || keys.at.origins.iter().any(|o| named_by(o, host));
    if !ours {
        return None;
    }
    let get = parts.method == hyper::Method::GET;
    let post = parts.method == hyper::Method::POST;
    let path = parts.uri.path();
    if get && let Some(file) = path.strip_prefix("/laye/web/") {
        return Some(web_file(inner, file));
    }
    let answered = match path {
        "/.well-known/webauthn" if get && host == keys.at.rp_id => passkeys::Answer {
            status: 200,
            body: keys.related(),
            session: None,
        },
        "/laye/me" if get => return Some(person_page(inner)),
        // "So laye has its own island?"
        // "I havent seen it yet."
        // laye's app proves who it is with its key and the account it is
        // bound to, as at /laye/login, and holds the session it is given
        // where the island reads one (ios-common island/app/WaitsNode.swift).
        APP_SESSION if post => {
            let (_, person, level) = match laye_of(inner).proven(body) {
                Ok(proven) => proven,
                Err((status, _, text)) => {
                    return Some(json(
                        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                        text,
                    ));
                }
            };
            let t = now();
            match passkeys::session_of(&person, level, &inner.did, &inner.key, t) {
                Ok(token) => passkeys::Answer {
                    status: 200,
                    body: serde_json::json!({
                        "person": person, "level": level, "session": token,
                        "until": t + passkeys::SESSION_LIFE,
                    }),
                    session: Some(token),
                },
                Err(why) => passkeys::Answer {
                    status: 500,
                    body: serde_json::json!({ "error": format!("the session was not signed: {why}") }),
                    session: None,
                },
            }
        }
        "/laye/challenge" if get => {
            let (status, _, text) = laye_of(inner).challenge();
            return Some(json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                text,
            ));
        }
        "/laye/passkey/me" if get => match session_asking(inner, parts) {
            Ok((person, level, until)) => {
                let shown = shown_for(inner, keys, &person).await;
                passkeys::Answer {
                    status: 200,
                    body: serde_json::json!({
                        "person": person, "level": level, "until": until,
                        "name": shown.name, "picture": shown.picture, "account": shown.account,
                    }),
                    session: None,
                }
            }
            Err(why) => passkeys::Answer {
                status: 401,
                body: serde_json::json!({ "error": why }),
                session: None,
            },
        },
        "/laye/passkey/enrol/begin" if post => match serde_json::from_slice::<door::Login>(body) {
            Ok(login) => match laye_of(inner).first_half(&login) {
                Ok(first) => keys.enrol_begin(first, shown_in(body), now()),
                Err((status, why)) => passkeys::Answer {
                    status,
                    body: serde_json::json!({ "error": why }),
                    session: None,
                },
            },
            Err(e) => passkeys::Answer {
                status: 400,
                body: serde_json::json!({ "error": format!("the login does not read: {e}") }),
                session: None,
            },
        },
        "/laye/passkey/enrol/finish" if post => {
            keys.enrol_finish(body, &inner.did, &inner.key, now()).await
        }
        "/laye/passkey/signin/begin" if post => keys.sign_in_begin(body, now()).await,
        "/laye/passkey/signin/finish" if post => {
            let laye = laye_of(inner);
            keys.sign_in_finish(
                body,
                |kept| laye.still_vouched(&kept.person, &kept.level, kept.binding.as_ref()),
                &inner.did,
                &inner.key,
                now(),
            )
            .await
        }
        "/laye/device" if post => {
            let asked = issuer::form(&String::from_utf8_lossy(body));
            let field = |name: &str| asked.get(name).map_or("", |v| v.trim());
            let (status, body) = devices_of(inner, keys)
                .ask(field("did"), field("label"), now())
                .await;
            return Some(json(code(status), body.to_string()));
        }
        "/laye/device/token" if post => {
            let asked = issuer::form(&String::from_utf8_lossy(body));
            let device_code = asked.get("device_code").map_or("", |v| v.trim());
            let (status, body) = devices_of(inner, keys).token(device_code, now()).await;
            return Some(json(code(status), body.to_string()));
        }
        "/laye/device/shown" | "/laye/device/approve" => {
            // A key never says yes for a person: only their passkey session does.
            let (person, level) = match person_asking(inner, parts) {
                Ok(who) => who,
                Err(why) => {
                    return Some(json(
                        StatusCode::UNAUTHORIZED,
                        serde_json::json!({ "error": why }).to_string(),
                    ));
                }
            };
            let devices = devices_of(inner, keys);
            let (status, body) = if path == "/laye/device/shown" && get {
                let query = issuer::form(parts.uri.query().unwrap_or_default());
                let user_code = query.get("user_code").map_or("", String::as_str);
                devices.shown(user_code, now()).await
            } else if path == "/laye/device/approve" && post {
                #[derive(Deserialize)]
                struct Asked {
                    user_code: String,
                }
                match serde_json::from_slice::<Asked>(body) {
                    Ok(asked) => {
                        devices
                            .approve(&asked.user_code, &person, &level, now())
                            .await
                    }
                    Err(e) => (
                        400,
                        serde_json::json!({ "error": format!("a yes is {{\"user_code\"}}: {e}") }),
                    ),
                }
            } else {
                return None;
            };
            return Some(json(code(status), body.to_string()));
        }
        // "kept. kept bro, i want to put my finger on, and then not have to thing about it anymore"
        // 「[Opus 5.5] mycelia's door: the journey opens here, the passkey is done」
        // 「[Opus 5.5] on laye's page, and the browser goes back with a ticket.」
        "/laye/door/home" if get => {
            let query = issuer::form(parts.uri.query().unwrap_or_default());
            let door = query.get("door").map_or("", String::as_str);
            let ticket = match inner.journeys.open(door, now()) {
                Ok(ticket) => ticket,
                Err(why) => {
                    return Some(json(
                        StatusCode::UNAUTHORIZED,
                        serde_json::json!({ "error": why }).to_string(),
                    ));
                }
            };
            let mut resp = said(StatusCode::FOUND, "");
            let headers = resp.headers_mut();
            headers.insert(
                hyper::header::LOCATION,
                hyper::header::HeaderValue::from_static("/laye/me?door=1"),
            );
            if let Ok(cookie) = hyper::header::HeaderValue::from_str(&door_cookie(Some(&ticket))) {
                headers.insert(hyper::header::SET_COOKIE, cookie);
            }
            return Some(resp);
        }
        "/laye/door/send" if post => {
            let (person, level) = match person_asking(inner, parts) {
                Ok(who) => who,
                Err(why) => {
                    return Some(json(
                        StatusCode::UNAUTHORIZED,
                        serde_json::json!({ "error": why }).to_string(),
                    ));
                }
            };
            let ticket = cookie_of(parts, mycelia_door::COOKIE).unwrap_or_default();
            let (status, body) =
                match inner
                    .journeys
                    .send(ticket, &person, &level, &inner.did, &inner.key, now())
                {
                    Ok(to) => (200, serde_json::json!({ "to": to })),
                    Err((status, why)) => (status, serde_json::json!({ "error": why })),
                };
            let mut resp = json(code(status), body.to_string());
            if let Ok(cookie) = hyper::header::HeaderValue::from_str(&door_cookie(None)) {
                resp.headers_mut().insert(hyper::header::SET_COOKIE, cookie);
            }
            return Some(resp);
        }
        "/laye/door/home/result" if get => {
            let query = issuer::form(parts.uri.query().unwrap_or_default());
            let ticket = query.get("home").map_or("", String::as_str);
            let door = query.get("door").map_or("", String::as_str);
            let (status, body) = match inner.journeys.collect(ticket, door, now()) {
                Ok(got) => {
                    let shown = shown_for(inner, keys, &got.person).await;
                    (
                        200,
                        serde_json::json!({
                            "admitted_as": got.person,
                            "name": shown.name,
                            "picture": shown.picture,
                            "until": got.until,
                            "session": got.token,
                        }),
                    )
                }
                Err((status, why)) => (status, serde_json::json!({ "error": why })),
            };
            return Some(json(code(status), body.to_string()));
        }
        // "ag's presses go to laye"
        // 「[Opus 5.5] A press as ag makes it at the node, /api/collected/<act> with」
        // 「[Opus 5.5] {"to", ...}, is made here at /laye/collected/<act>.」
        // A press on laye's island asks under /api/, as every island's press
        // does (ios-common island/app/WaitsNode.swift): the same act.
        _ if post
            && path
                .strip_prefix("/api")
                .unwrap_or(path)
                .strip_prefix("/laye/collected/")
                .is_some_and(|act| ACTS.contains(&act)) =>
        {
            let act = path
                .strip_prefix("/api")
                .unwrap_or(path)
                .strip_prefix("/laye/collected/")
                .unwrap_or_default();
            let (person, level) = match collecting_for(inner, parts) {
                Ok(who) => who,
                Err(why) => {
                    return Some(json(
                        StatusCode::UNAUTHORIZED,
                        serde_json::json!({ "error": why }).to_string(),
                    ));
                }
            };
            let held = collected::Collections {
                etcd: &keys.etcd,
                laye: &inner.did,
            };
            let (status, body) = act_on(inner, &held, &person, &level, Some(act), body).await;
            return Some(json(code(status), body.to_string()));
        }
        "/api/phones" if post => {
            // The tokens Apple gave laye's app, handed in the person's session,
            // where every island hands them (ios-common island/app/WaitsTokens.swift).
            let (person, _) = match collecting_for(inner, parts) {
                Ok(who) => who,
                Err(why) => {
                    return Some(json(
                        StatusCode::UNAUTHORIZED,
                        serde_json::json!({ "error": why }).to_string(),
                    ));
                }
            };
            let handed = match serde_json::from_slice::<island::Handed>(body) {
                Ok(handed) => handed,
                Err(e) => {
                    return Some(said(
                        StatusCode::BAD_REQUEST,
                        format!(
                            "a phone's token is {{\"token\", \"waits\", \"phone\", \"gone\"}}: {e}"
                        ),
                    ));
                }
            };
            let held = collected::Collections {
                etcd: &keys.etcd,
                laye: &inner.did,
            };
            return Some(match island::keep(&held, &person, &handed, now()).await {
                Ok(()) => json(StatusCode::OK, String::from("{}")),
                Err(why) => said(StatusCode::BAD_REQUEST, why),
            });
        }
        "/laye/collected" | "/laye/collected/act" => {
            // "and as a human i can dial it"
            // What waits is the person's to see and to act on, in their
            // passkey session or the one mycelia's door collected for them:
            // no key does either.
            let (person, level) = match collecting_for(inner, parts) {
                Ok(who) => who,
                Err(why) => {
                    return Some(json(
                        StatusCode::UNAUTHORIZED,
                        serde_json::json!({ "error": why }).to_string(),
                    ));
                }
            };
            let held = collected::Collections {
                etcd: &keys.etcd,
                laye: &inner.did,
            };
            let (status, body) = if path == "/laye/collected" && get {
                collected_for(&held, &person, &level).await
            } else if path == "/laye/collected/act" && post {
                act_on(inner, &held, &person, &level, None, body).await
            } else {
                return None;
            };
            return Some(json(code(status), body.to_string()));
        }
        "/laye/person" if post => {
            // A person's name and photo, as the provider showed them: taken
            // only with a binding that is theirs, signed by a key laye trusts.
            let (person, _) = match person_asking(inner, parts) {
                Ok(who) => who,
                Err(why) => {
                    return Some(json(
                        StatusCode::UNAUTHORIZED,
                        serde_json::json!({ "error": why }).to_string(),
                    ));
                }
            };
            let (status, words) = shown_by(inner, keys, &person, body).await;
            return Some(json(code(status), words.to_string()));
        }
        "/laye/passkey/out" if post => {
            let mut resp = json(StatusCode::OK, "{}");
            if let Ok(cookie) = hyper::header::HeaderValue::from_str(&session_cookie(None)) {
                resp.headers_mut().insert(hyper::header::SET_COOKIE, cookie);
            }
            return Some(resp);
        }
        _ => return None,
    };
    let mut resp = json(
        StatusCode::from_u16(answered.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        answered.body.to_string(),
    );
    if let Some(token) = answered.session
        && let Ok(cookie) = hyper::header::HeaderValue::from_str(&session_cookie(Some(&token)))
    {
        resp.headers_mut().insert(hyper::header::SET_COOKIE, cookie);
    }
    Some(resp)
}

/// Whether `person`, at `level`, sees and acts on what waits for `did`: the
/// agent is theirs, or they are a root.
async fn theirs(held: &collected::Collections<'_>, did: &str, person: &str, level: &str) -> bool {
    level == issuer::ROOT
        || held
            .person_of_agent(did)
            .await
            .is_ok_and(|whose| whose == person)
}

/// What waits for the agents a person sees.
async fn collected_for(
    held: &collected::Collections<'_>,
    person: &str,
    level: &str,
) -> (u16, serde_json::Value) {
    let all = match held.all().await {
        Ok(all) => all,
        Err(why) => return (503, serde_json::json!({ "error": why })),
    };
    let mut seen = Vec::new();
    for one in all {
        if (!one.waiting.is_empty() || !one.held_until.is_empty())
            && theirs(held, &one.did, person, level).await
        {
            seen.push(one);
        }
    }
    (200, serde_json::json!({ "collected": seen }))
}

/// Where laye hands QNTX what a person released, or what came due, for
/// QNTX's own agent (QNTX server/auth/laye_delivered.go).
const DELIVERED_TO_NODE: &str = "/auth/laye/delivered";

/// laye's signature for one request to QNTX.
fn signed_for_qntx(inner: &Inner) -> Result<String, String> {
    let t = now();
    jwt::sign(
        &inner.key,
        &jwt::Claims {
            iss: inner.did.clone(),
            sub: inner.did.clone(),
            aud: vec![inner.config.qntx_did.clone()],
            exp: t + 60,
            iat: t,
            jti: jwt::fresh_jti(),
            label: "laye".into(),
        },
    )
    .map(|signed| format!("Signed {signed}"))
    .map_err(|e| e.to_string())
}

/// "yeah, because right now, i dont even see the outgoing towards node agent in ag right? yeah thats fucked up as well"
///
/// Each delivery of what was collected for QNTX's own agent, handed to QNTX,
/// which runs it as the agent's turn; once QNTX took it, it is gone from the
/// news. What QNTX did not take stays, and is handed again. Why each one was
/// not handed.
async fn hand_to_node(inner: &Inner, etcd: &etcd::Etcd) -> Vec<String> {
    let all = match etcd.under(collected::NEWS).await {
        Ok(all) => all,
        Err(why) => return vec![why],
    };
    let mut failed = Vec::new();
    for (key, kv) in all {
        let Ok(news) = serde_json::from_slice::<collected::News>(&kv.value) else {
            continue;
        };
        if !news.node {
            continue;
        }
        let signed = match signed_for_qntx(inner) {
            Ok(signed) => signed,
            Err(why) => {
                failed.push(why);
                continue;
            }
        };
        let body = serde_json::json!({
            "did": news.did, "to": news.to, "from": news.from, "says": news.note, "tasks": news.tasks,
        });
        let Ok(req) = Request::post(format!("{}{DELIVERED_TO_NODE}", inner.config.qntx))
            .header(hyper::header::AUTHORIZATION, signed)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
        else {
            failed.push(format!("the delivery to {} was not made", news.to));
            continue;
        };
        let resp = match inner.client.request(req).await {
            Ok(resp) => resp,
            Err(e) => {
                failed.push(format!("{}: QNTX did not answer: {e}", news.to));
                continue;
            }
        };
        let status = resp.status();
        let answered = resp
            .into_body()
            .collect()
            .await
            .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
            .unwrap_or_default();
        if !status.is_success() {
            failed.push(format!("{}: QNTX answered {status} {answered}", news.to));
            continue;
        }
        if let Err(why) = etcd.txn(&[], vec![etcd::Op::Delete(key.clone())]).await {
            failed.push(format!(
                "{} was handed to QNTX and {key} stays: {why}",
                news.to
            ));
            continue;
        }
        eprintln!(
            "laye-front: what was released for {} is handed to QNTX: {answered}",
            news.to
        );
    }
    failed
}

/// Where laye asks QNTX, the primary, to write an approved reach line on a peer.
const REACH_ON_PEER: &str = "/auth/laye/reach";

/// Where laye asks QNTX, the primary, to admit an approved key on a peer.
const ADMIT_ON_PEER: &str = "/auth/laye/admit";

/// "i dont want to do it. i am pleasing begging for it to be via ag and live activity via laye"
///
/// Writes each reach line, and admits each key, among what is released, as
/// the person who released it, through the primary. Each one done says so in
/// what is delivered; one that is not stops the release, with why.
async fn reach_approved(
    inner: &Inner,
    held: &collected::Collections<'_>,
    did: &str,
    ids: &[String],
    person: &str,
) -> Result<(), String> {
    let all = held.all().await?;
    for one in all
        .into_iter()
        .filter(|c| c.did == did)
        .flat_map(|c| c.waiting)
    {
        let (path, asked, line, peer) = if let Some(reach) = one.reach.as_ref() {
            (
                REACH_ON_PEER,
                serde_json::json!({
                    "person": person, "peer": reach.peer, "path": reach.path, "to": reach.to,
                }),
                reach.line(),
                reach.peer.clone(),
            )
        } else if let Some(admit) = one.admit.as_ref() {
            (
                ADMIT_ON_PEER,
                serde_json::json!({
                    "person": person, "peer": admit.peer, "did": admit.did, "label": admit.label,
                }),
                admit.line(),
                admit.peer.clone(),
            )
        } else {
            continue;
        };
        if !ids.is_empty() && !ids.contains(&one.id) {
            continue;
        }
        let t = now();
        let signed = jwt::sign(
            &inner.key,
            &jwt::Claims {
                iss: inner.did.clone(),
                sub: inner.did.clone(),
                aud: vec![inner.config.qntx_did.clone()],
                exp: t + 60,
                iat: t,
                jti: jwt::fresh_jti(),
                label: "laye".into(),
            },
        )
        .map_err(|e| e.to_string())?;
        let req = Request::post(format!("{}{path}", inner.config.qntx))
            .header(hyper::header::AUTHORIZATION, format!("Signed {signed}"))
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(asked.to_string())))
            .map_err(|e| e.to_string())?;
        let resp = inner
            .client
            .request(req)
            .await
            .map_err(|e| format!("QNTX did not answer: {e}"))?;
        let status = resp.status();
        let answered = resp
            .into_body()
            .collect()
            .await
            .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
            .unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "{line} was not done on {peer}: {status} {answered}"
            ));
        }
        eprintln!("laye-front: {person} approved {line} on {peer}, and it is done");
        held.act(
            did,
            None,
            &collected::Act::Edit {
                id: one.id.clone(),
                says: format!("{person} approved, and it is done on {peer}: {line}"),
            },
            person,
            now(),
        )
        .await?;
    }
    Ok(())
}

/// What a person does with what waits for an agent.
const ACTS: [&str; 5] = ["release", "hold", "later", "cancel", "edit"];

/// A person's act on what waits for one agent:
/// {"did", "act": release|hold|later|cancel|edit, "collection", "ids", "says", "until", "id"}.
/// `collection` is the one acted on; without it, each the act is of.
/// An act the path names stands for the body's, and `to` for `did`, as ag
/// asks the node (QNTX server/collected.go).
async fn act_on(
    inner: &Inner,
    held: &collected::Collections<'_>,
    person: &str,
    level: &str,
    named: Option<&str>,
    body: &[u8],
) -> (u16, serde_json::Value) {
    #[derive(Deserialize)]
    struct Asked {
        #[serde(alias = "to")]
        did: String,
        #[serde(default)]
        act: String,
        #[serde(default)]
        collection: Option<String>,
        #[serde(default)]
        ids: Vec<String>,
        #[serde(default)]
        says: Option<String>,
        #[serde(default)]
        until: Option<String>,
        #[serde(default)]
        id: Option<String>,
    }
    let refused = |status: u16, why: String| (status, serde_json::json!({ "error": why }));
    let asked: Asked = match serde_json::from_slice(body) {
        Ok(asked) => asked,
        Err(e) => return refused(400, format!("an act is {{\"did\", \"act\"}}: {e}")),
    };
    if !theirs(held, &asked.did, person, level).await {
        return refused(
            403,
            format!("what waits for {} is not {person}'s to act on", asked.did),
        );
    }
    let says = asked.says.filter(|s| !s.trim().is_empty());
    let act = match named.unwrap_or(asked.act.as_str()) {
        // One thing approved by its id, as ag and the island press it.
        "release" => collected::Act::Release {
            ids: if asked.ids.is_empty() {
                asked.id.clone().into_iter().collect()
            } else {
                asked.ids
            },
            says,
        },
        "later" => collected::Act::Later,
        "cancel" => collected::Act::Cancel { id: asked.id },
        "hold" => match asked.until.as_deref().map(collected::secs) {
            Some(until) if until > 0 => collected::Act::Hold { until },
            _ => return refused(400, "hold takes until, as RFC 3339".into()),
        },
        "edit" => match (asked.id, says) {
            (Some(id), Some(says)) => collected::Act::Edit { id, says },
            _ => return refused(400, "edit takes the id and what it says".into()),
        },
        other => {
            return refused(
                400,
                format!("{other:?} is no act: release, hold, later, cancel, edit"),
            );
        }
    };
    // A reach line asked for is written before what waits is released: the
    // asker hears that it was written, or nothing is released.
    if let collected::Act::Release { ids, .. } = &act
        && let Err(why) = reach_approved(inner, held, &asked.did, ids, person).await
    {
        return refused(502, why);
    }
    let collection = asked.collection.as_deref().filter(|c| !c.is_empty());
    match held.act(&asked.did, collection, &act, person, now()).await {
        // One collection acted on is answered as itself, as it always was.
        Ok(mut after) if after.len() == 1 => (200, serde_json::json!(after.remove(0))),
        Ok(after) => (200, serde_json::json!({ "collected": after })),
        Err(why) => refused(409, why),
    }
}

// "why do you make the user click on, if your photo doesnt show here, thing."
//
/// What a person is shown as: what laye keeps, or else what laye can find
/// itself, which it then keeps. The account is the one their passkey's
/// binding proved. The name and photo are their record at the node, asked as
/// a key they said yes to; kept, they show while the node is down too.
/// Nothing here asks the person to do anything.
async fn shown_for(inner: &Inner, keys: &passkeys::Passkeys, person: &str) -> passkeys::Shown {
    let mut shown = passkeys::shown_of(&keys.etcd, person)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    if !shown.name.is_empty() && !shown.picture.is_empty() && !shown.account.is_empty() {
        return shown;
    }
    let before = shown.clone();
    if shown.account.is_empty() {
        shown.account = account_of(keys, person).await.unwrap_or_default();
    }
    if (shown.name.is_empty() || shown.picture.is_empty())
        && let Some(record) = record_of(inner, keys, person).await
    {
        let field = |name: &str| {
            record
                .get(name)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        if shown.picture.is_empty() {
            shown.picture = field("picture");
        }
        if shown.name.is_empty() {
            shown.name = field("display_name");
        }
    }
    if shown.name.is_empty() {
        shown.name = shown.account.clone();
    }
    if shown != before
        && let Ok(value) = serde_json::to_vec(&shown)
        && let Err(why) = keys
            .etcd
            .txn(
                &[],
                vec![etcd::Op::Put(
                    format!("{}{person}", passkeys::PEOPLE),
                    value,
                )],
            )
            .await
    {
        eprintln!("laye-front: what {person} is shown as was not kept: {why}");
    }
    shown
}

/// The account a person's passkey was made on, as its provider names it.
async fn account_of(keys: &passkeys::Passkeys, person: &str) -> Option<String> {
    let all = keys.etcd.under(passkeys::PASSKEYS).await.ok()?;
    all.iter().find_map(|(_, kv)| {
        let kept: passkeys::Passkey = serde_json::from_slice(&kv.value).ok()?;
        let binding = kept.binding.filter(|_| kept.person == person)?;
        Some(binding.claim.handle.unwrap_or(binding.claim.canonical_id))
    })
}

/// The person's record at the node (QNTX `/i/`), asked as a key they said
/// yes to at laye. None when no such key is kept, or the node did not answer.
async fn record_of(
    inner: &Inner,
    keys: &passkeys::Passkeys,
    person: &str,
) -> Option<serde_json::Value> {
    let theirs = keys.etcd.under(devices::KEYS).await.ok()?;
    let key = theirs.iter().find_map(|(at, kv)| {
        let yes: devices::Yes = serde_json::from_slice(&kv.value).ok()?;
        if yes.person != person {
            return None;
        }
        at.strip_prefix(devices::KEYS).map(str::to_string)
    })?;
    let resp = forward(
        inner,
        hyper::Version::HTTP_11,
        &hyper::Method::GET,
        "/i/",
        &[],
        Some(&key),
        Bytes::new(),
    )
    .await
    .ok()?;
    if resp.status() != StatusCode::OK {
        return None;
    }
    let body = resp.into_body().collect().await.ok()?.to_bytes();
    serde_json::from_slice(&body).ok()
}

/// What a person is shown as, when a page sends it beside what it asks.
fn shown_in(body: &[u8]) -> Option<passkeys::Shown> {
    let asked: serde_json::Value = serde_json::from_slice(body).ok()?;
    serde_json::from_value(asked.get("shown")?.clone()).ok()
}

/// Keeps what `person` is shown as, from the provider's answer to a ceremony
/// that proved the account `person` is.
async fn shown_by(
    inner: &Inner,
    keys: &passkeys::Passkeys,
    person: &str,
    body: &[u8],
) -> (u16, serde_json::Value) {
    #[derive(Deserialize)]
    struct Asked {
        binding: laye_me::SignedBinding,
        shown: passkeys::Shown,
    }
    let refused = |status: u16, why: String| (status, serde_json::json!({ "error": why }));
    let asked: Asked = match serde_json::from_slice(body) {
        Ok(asked) => asked,
        Err(e) => return refused(400, format!("this is {{\"binding\", \"shown\"}}: {e}")),
    };
    if asked.binding.claim.canonical_id != person {
        return refused(403, format!("the account proven is not {person}"));
    }
    if asked.binding.verify().is_err()
        || !inner
            .config
            .binding_signers
            .contains(&door::hex(&asked.binding.signer_pubkey))
    {
        return refused(403, "the binding is not signed by a key laye trusts".into());
    }
    let value = match serde_json::to_vec(&asked.shown) {
        Ok(value) => value,
        Err(e) => return refused(500, e.to_string()),
    };
    match keys
        .etcd
        .txn(
            &[],
            vec![etcd::Op::Put(
                format!("{}{person}", passkeys::PEOPLE),
                value,
            )],
        )
        .await
    {
        Ok(_) => (200, serde_json::json!(asked.shown)),
        Err(why) => refused(503, why),
    }
}

fn code(status: u16) -> StatusCode {
    StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// The device flow, at the etcd passkeys are kept in; the person says yes at
/// laye's page on the first origin its passkeys answer at.
fn devices_of<'a>(inner: &'a Inner, keys: &'a passkeys::Passkeys) -> devices::Devices<'a> {
    devices::Devices {
        etcd: &keys.etcd,
        approve_at: keys.at.origins.first().map_or("", String::as_str),
        laye: &inner.did,
    }
}

/// laye's page for a person: their passkey, and who laye knows them as.
fn person_page(inner: &Inner) -> Response<Body> {
    let page = include_str!("me.html")
        .replace(
            "{{ceremony}}",
            &serde_json::to_string(&inner.config.ceremony_at).unwrap_or_default(),
        )
        .replace(
            "{{signers}}",
            &serde_json::to_string(&inner.config.binding_signers).unwrap_or_default(),
        )
        // Each provider's mark, as QNTX-Web's door draws it (ts/provider-marks.ts).
        .replace("{{marks}}", include_str!("marks.json"));
    let mut resp = said(StatusCode::OK, page);
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

/// What vitreous ships (its package.json files): the glass laye's pages wear.
const VITREOUS: [&str; 6] = [
    "vitreous/vitreous.css",
    "vitreous/glass.css",
    "vitreous/shadow.css",
    "vitreous/motion.css",
    "vitreous/hover.css",
    "vitreous/click.css",
];

/// laye's wasm, the JS that loads it, and vitreous's stylesheets, from laye-web.
fn web_file(inner: &Inner, file: &str) -> Response<Body> {
    let kind = match file {
        "laye_p2p.js" => "text/javascript",
        "laye_p2p_bg.wasm" => "application/wasm",
        _ if VITREOUS.contains(&file) => "text/css",
        _ => {
            return said(
                StatusCode::NOT_FOUND,
                "laye serves its wasm, its JS and vitreous's stylesheets, and nothing else here",
            );
        }
    };
    let Some(dir) = &inner.web else {
        return said(
            StatusCode::SERVICE_UNAVAILABLE,
            "laye does not know where its wasm is",
        );
    };
    match std::fs::read(dir.join(file)) {
        Ok(bytes) => {
            let mut resp = Response::new(whole(bytes));
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static(kind),
            );
            resp
        }
        Err(e) => said(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("laye's wasm is not at {}: {e}", dir.display()),
        ),
    }
}

/// What laye answers itself, at its own name: where people log in. Anything
/// else, and every other name, goes on to QNTX.
fn as_laye(
    inner: &Inner,
    parts: &hyper::http::request::Parts,
    body: &[u8],
) -> Option<Response<Body>> {
    if !at_laye(inner, parts) {
        return None;
    }
    let laye = laye_of(inner);
    let get = parts.method == hyper::Method::GET;
    let post = parts.method == hyper::Method::POST;
    let (status, kind, text) = match parts.uri.path() {
        "/.well-known/oauth-authorization-server" if get => laye.metadata(),
        "/auth/authorize" if get => laye.authorize(parts.uri.query().unwrap_or_default()),
        "/laye/challenge" if get => laye.challenge(),
        "/laye/back" if get => laye.back(),
        "/laye/login" if post => laye.login(body),
        "/auth/token" if post => laye.token(body),
        "/auth/introspect" if post => laye.introspect(body),
        "/laye/roots" if post => laye.roots(body),
        "/laye/invitations" | "/laye/invitations/withdraw" => {
            // "and i own the invites"
            // A root's own key, or a root in its passkey session at laye's page.
            let signer = match signer_of(inner, parts) {
                Ok(Some(signer)) => Some(signer),
                Ok(None) => person_asking(inner, parts).ok().map(|(person, _)| person),
                Err(why) => return Some(said(StatusCode::UNAUTHORIZED, why)),
            };
            match (parts.uri.path(), get, post) {
                ("/laye/invitations", true, _) => laye.invitations(signer.as_deref()),
                ("/laye/invitations", _, true) => laye.invite(signer.as_deref(), body),
                ("/laye/invitations/withdraw", _, true) => laye.withdraw(signer.as_deref(), body),
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(answered((status, kind, text)))
}

/// Whether a request is to laye's own name.
fn at_laye(inner: &Inner, parts: &hyper::http::request::Parts) -> bool {
    let host = parts
        .headers
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    inner
        .config
        .issuer
        .split_once("://")
        .is_some_and(|(_, name)| name.trim_end_matches('/') == host)
}

/// An issuer's answer, as a response.
fn answered((status, kind, text): issuer::Said) -> Response<Body> {
    let mut resp = said(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        text,
    );
    if let Ok(kind) = hyper::header::HeaderValue::from_str(kind) {
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, kind);
    }
    resp
}

// "BUT I WANT LAYE TO OWN IT, LAYE IS SUPPOSED TO FALL DOWN LESS EASILY THAN QNTX"
//
/// The connectors' authorization server, at laye's own name, in the etcd laye
/// keeps passkeys in: a client laye issues for is answered here, and any
/// other goes on to the node's sign-in below (as_laye).
async fn as_connectors(
    inner: &Inner,
    parts: &hyper::http::request::Parts,
    body: &Bytes,
) -> Option<Response<Body>> {
    let keys = inner.passkeys.as_ref()?;
    if !at_laye(inner, parts) {
        return None;
    }
    let laye = laye_of(inner);
    let etcd = &keys.etcd;
    let get = parts.method == hyper::Method::GET;
    let post = parts.method == hyper::Method::POST;
    let known = |found: Result<Option<connectors::Client>, String>| match found {
        Ok(found) => found.map(Ok),
        Err(why) => Some(Err(said(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("laye did not read its connectors: {why}"),
        ))),
    };
    let answer = match parts.uri.path() {
        "/auth/authorize" if get => {
            let query = parts.uri.query().unwrap_or_default();
            let asked = issuer::form(query);
            let id = asked.get("client_id").cloned().unwrap_or_default();
            match known(connectors::client(etcd, &id).await)? {
                Ok(client) => connectors::authorize(&laye, &client, query),
                Err(refused) => return Some(refused),
            }
        }
        "/laye/login" if post => {
            #[derive(Deserialize)]
            struct Journey {
                authorize: String,
            }
            let journey = serde_json::from_slice::<Journey>(body).ok()?;
            let asked = issuer::form(&journey.authorize);
            let id = asked.get("client_id").cloned().unwrap_or_default();
            match known(connectors::client(etcd, &id).await)? {
                Ok(client) => {
                    connectors::login(&laye, etcd, &client, &journey.authorize, body).await
                }
                Err(refused) => return Some(refused),
            }
        }
        "/auth/token" if post => {
            let asked = issuer::form(&String::from_utf8_lossy(body));
            let authorization = parts
                .headers
                .get(hyper::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            let (id, secret) = connectors::presented(authorization, &asked);
            let client = match known(connectors::client(etcd, &id).await)? {
                Ok(client) => client,
                Err(refused) => return Some(refused),
            };
            match connectors::token(&laye, etcd, &client, &secret, &asked).await {
                connectors::Answered::Said(answer) => answer,
                // A refresh token QNTX issued, before laye issued for the
                // connectors: QNTX answers it, as it did.
                connectors::Answered::NotLayes => {
                    let headers = passed_on(parts);
                    return Some(
                        match forward(
                            inner,
                            parts.version,
                            &parts.method,
                            "/auth/token",
                            &headers,
                            None,
                            body.clone(),
                        )
                        .await
                        {
                            Ok(resp) => resp,
                            Err(why) => said(
                                StatusCode::SERVICE_UNAVAILABLE,
                                format!(
                                    "QNTX did not answer for the refresh token it issued: {why}"
                                ),
                            ),
                        },
                    );
                }
            }
        }
        "/auth/introspect" if post => connectors::introspect(&laye, etcd, body).await,
        _ => return None,
    };
    Some(answered(answer))
}

/// The key a request is signed by, when it carries a signature: checked as a
/// session's is. None is a request that carries none.
fn signer_of(inner: &Inner, parts: &hyper::http::request::Parts) -> Result<Option<String>, String> {
    match parts
        .headers
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix(SIGNED))
    {
        Some(token) => who_signed(inner, token.trim()).map(Some),
        None => Ok(None),
    }
}

fn said(status: StatusCode, words: impl Into<String>) -> Response<Body> {
    let mut resp = Response::new(whole(words.into()));
    *resp.status_mut() = status;
    resp
}

/// What is collected for the person asking, pushed as it changes, at laye's
/// own names; None for anything else.
fn watch_collected(
    inner: &Arc<Inner>,
    parts: &hyper::http::request::Parts,
) -> Option<Response<Body>> {
    let keys = inner.passkeys.as_ref()?;
    let host = host_of(parts);
    let ours =
        named_by(&inner.config.issuer, host) || keys.at.origins.iter().any(|o| named_by(o, host));
    if !ours || parts.method != hyper::Method::GET || parts.uri.path() != "/laye/collected/watch" {
        return None;
    }
    let (person, level) = match collecting_for(inner, parts) {
        Ok(who) => who,
        Err(why) => {
            return Some(json(
                StatusCode::UNAUTHORIZED,
                serde_json::json!({ "error": why }).to_string(),
            ));
        }
    };
    let mut resp = Response::new(watched::watch(inner.clone(), person, level).boxed());
    let headers = resp.headers_mut();
    headers.insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/event-stream"),
    );
    headers.insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    Some(resp)
}

// "its the story of someone verifying they can trust laye the network they are about to join, with their agent"
// "can't we have it work in a way that we dont need to build the same parser twice?"
//
/// What ground's pbt says of a laye, as `ground laye json` writes it
/// (Ground-Code source/administers.d asData): laye reads it, and no pbt.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Governed {
    /// The laye the pbt names.
    pub url: String,
    /// The org that governs it.
    pub org: String,
    /// The person who administers that org.
    pub administrator: String,
}

/// Where laye says whether the account a name is administers it.
const ADMINISTRATOR: &str = "/laye/administrator/";

/// Whether the account a name is administers this laye, as ground says; and
/// nothing else about anyone. A laye ground said nothing of says so.
fn administers(governed: Option<&Governed>, name: &str) -> Response<Body> {
    let Some(governed) = governed else {
        return said(
            StatusCode::SERVICE_UNAVAILABLE,
            "this laye was given nothing ground says of it: its settings name no governed_by",
        );
    };
    json(
        StatusCode::OK,
        serde_json::json!({ "administrator": name, "administers": governed.administrator == name })
            .to_string(),
    )
}

async fn answer(inner: &Arc<Inner>, mut req: Request<hyper::body::Incoming>) -> Response<Body> {
    // A request asking to upgrade (QNTX's page's WebSocket) is carried
    // through once both sides have switched.
    let upgrading = req
        .headers()
        .contains_key(hyper::header::UPGRADE)
        .then(|| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
    if let Some(watching) = watch_collected(inner, &parts) {
        return watching;
    }
    if parts.method == hyper::Method::GET
        && let Some(name) = parts.uri.path().strip_prefix(ADMINISTRATOR)
    {
        return administers(inner.config.governed.as_ref(), name);
    }
    let body = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            return said(
                StatusCode::BAD_REQUEST,
                format!("the body did not arrive: {e}"),
            );
        }
    };

    if let Some(answered) = as_person(inner, &parts, &body).await {
        return answered;
    }

    if let Some(answered) = as_connectors(inner, &parts, &body).await {
        return answered;
    }

    let inviting = parts.method == hyper::Method::POST && parts.uri.path() == "/laye/invitations";
    if let Some(answered) = as_laye(inner, &parts, &body) {
        if inviting && answered.status() == StatusCode::OK {
            return mailed(inner, answered).await;
        }
        return answered;
    }

    // The card is laye's own, QNTX up or not: laye is where agents are reached.
    if is_the_card(&parts) {
        return match a2a_card::card(origin_of(inner, &parts), &inner.did, &inner.key) {
            Ok(card) => json(StatusCode::OK, card),
            Err(why) => said(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("laye's card was not made: {why}"),
            ),
        };
    }

    // Who is admitted, and the name a session holds, are laye's when it keeps
    // names: QNTX up or not.
    if let Some(names) = &inner.names
        && parts.method == hyper::Method::POST
        && matches!(parts.uri.path(), ADMIT_PATH | NAME_PATH)
    {
        return at_names(inner, names, &parts, body).await;
    }

    let presented = parts
        .headers
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix(SIGNED))
        .map(str::trim);
    let subject = match presented {
        Some(token) => match who_signed(inner, token) {
            Ok(subject) => Some(subject),
            Err(why) => return said(StatusCode::UNAUTHORIZED, why),
        },
        None => None,
    };

    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());

    // A session's own signature is laye's to read, and goes no further: laye
    // says who it is in its place. Any other credential is QNTX's own, a
    // session QNTX made and checks itself (QNTX-Web ts/client/session.ts),
    // and is handed on as it came. Taken away, every request of a person
    // logged in at QNTX reached it as a stranger, and their app asked them
    // to log in, again and again.
    let headers = passed_on(&parts);

    // "laye owning collections, with the island in laye."
    // What a person's connector says to a session arrives at QNTX, which
    // hands it here, signed as itself: it is collected, and goes when the
    // person releases it.
    if let (Some(keys), Some(subject)) = (&inner.passkeys, subject.as_deref())
        && subject == inner.config.qntx_did
        && parts.method == hyper::Method::POST
        && parts.uri.path() == CONNECTOR_SAID
    {
        return connector_said(inner, keys, &body).await;
    }

    // "SESSION CANT REACH, IT NEEDS REACH LINE(S), IT GETS IN FRONT OF MY VIA AG OR LIVE ACTIVITY AS SOMETHING TO APPROVE,"
    // A node that refused a request for reach hands laye what it lacked,
    // signed as itself: it waits in the person's pack.
    if let (Some(keys), Some(subject)) = (&inner.passkeys, subject.as_deref())
        && (subject == inner.config.qntx_did
            || inner.config.pack_nodes.iter().any(|n| n == subject))
        && parts.method == hyper::Method::POST
        && parts.uri.path() == REACH_LACKED
    {
        return reach_lacked(inner, keys, subject, &body).await;
    }

    // "CAN WE PLEASE STOP EXPECTING AN AGENT TO REQUEST IT OWN PERMISSIONS AND ALSO BE PERFECT?"
    // A node that holds nothing for a key that signed for it hands laye the
    // key, signed as itself: admitting it waits in its ROOT's pack.
    if let (Some(keys), Some(subject)) = (&inner.passkeys, subject.as_deref())
        && (subject == inner.config.qntx_did
            || inner.config.pack_nodes.iter().any(|n| n == subject))
        && parts.method == hyper::Method::POST
        && parts.uri.path() == KEY_UNKNOWN
    {
        return key_unknown(inner, keys, subject, &body).await;
    }

    // What an agent says to an agent, its Task, and the row it is delivered
    // on are laye's when it keeps passkeys: QNTX up or not.
    if let (Some(keys), Some(subject)) = (&inner.passkeys, subject.as_deref())
        && let Some(answered) = as_collections(inner, keys, &parts, &body, subject, &headers).await
    {
        return answered;
    }

    if let Some(upgrading) = upgrading {
        return carry_upgrade(
            inner,
            &parts.method,
            &path,
            &headers,
            subject.as_deref(),
            upgrading,
        )
        .await;
    }

    match forward(
        inner,
        parts.version,
        &parts.method,
        &path,
        &headers,
        subject.as_deref(),
        body.clone(),
    )
    .await
    {
        Ok(resp) => resp,
        Err(why) => {
            let send = (parts.method == hyper::Method::POST)
                .then(|| a2a_spoken::send_of(&path, &body))
                .flatten();
            match (subject, send) {
                (Some(subject), Some(send)) => keep(inner, path, headers, subject, &body, &send),
                _ if is_grpc(&parts) => unavailable_over_grpc(&why),
                _ => said(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("QNTX did not answer, and laye is still here: {why}"),
                ),
            }
        }
    }
}

/// Where a key the person said yes to admits a session's key (QNTX's
/// `/auth/admit`).
const ADMIT_PATH: &str = "/auth/admit";
/// Where a session names itself (QNTX's `i name`).
const NAME_PATH: &str = "/i/name";

/// An admission or a naming, answered by laye from what it keeps. What laye
/// gave is then handed to QNTX as every kept request is, so QNTX knows it too.
async fn at_names(
    inner: &Inner,
    names: &names::Names,
    parts: &hyper::http::request::Parts,
    body: Bytes,
) -> Response<Body> {
    let signer = match signer_of(inner, parts) {
        Ok(Some(signer)) => signer,
        Ok(None) => {
            return said(
                StatusCode::UNAUTHORIZED,
                "laye answers this to a key signing as itself",
            );
        }
        Err(why) => return said(StatusCode::UNAUTHORIZED, why),
    };
    let path = parts.uri.path();
    let (status, words) = if path == ADMIT_PATH {
        let asked = issuer::form(&String::from_utf8_lossy(&body));
        let field = |name: &str| asked.get(name).map_or("", |v| v.trim());
        names
            .admit(&signer, field("did"), field("label"), now())
            .await
    } else {
        #[derive(Deserialize)]
        struct Asked {
            name: String,
            #[serde(default)]
            given: Option<String>,
        }
        match serde_json::from_slice::<Asked>(&body) {
            Ok(asked) => {
                names
                    .name(&signer, &asked.name, asked.given.as_deref(), now())
                    .await
            }
            Err(e) => (
                400,
                format!("a name is asked for as {{\"name\": ...}}: {e}"),
            ),
        }
    };
    // An admission laye already holds (409) is told too: it may have been made
    // at another laye on the same etcd, and this QNTX not told of it.
    if status == 200 || (status == 409 && path == ADMIT_PATH) {
        let told = Held {
            path: path.to_string(),
            headers: passed_on(parts),
            body: B64.encode(&body),
            subject: signer,
        };
        if let Err(why) = hold(inner, told) {
            eprintln!("laye-front: QNTX will not be told of {path}: {why}");
        }
    }
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if status == StatusCode::OK {
        json(status, words)
    } else {
        said(status, words)
    }
}

/// A2A 1.0 over HTTP+JSON, beneath a tenant: `/a2a/<Name>/<rest>`.
fn at_a_name(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/a2a/")?;
    let (name, rest) = rest.split_once('/')?;
    (!name.is_empty() && !name.contains('.')).then_some((name, rest))
}

/// The agent holding a name at laye: its DID and the name as it holds it.
async fn named(etcd: &etcd::Etcd, name: &str) -> Result<Option<(String, String)>, String> {
    let name = name.replace("%20", " ");
    let Some(kv) = etcd
        .get(&format!("/names/{}", name.to_ascii_lowercase()))
        .await?
    else {
        return Ok(None);
    };
    let held: serde_json::Value = serde_json::from_slice(&kv.value)
        .map_err(|e| format!("the name {name} does not read: {e}"))?;
    Ok(held.get("did").and_then(|d| d.as_str()).map(|did| {
        let called = held
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or(&name)
            .to_string();
        (did.to_string(), called)
    }))
}

/// A Task laye answers with, in A2A 1.0's ProtoJSON.
fn task_json(t: &collected::Tasked) -> serde_json::Value {
    serde_json::json!({
        "id": t.id,
        "contextId": t.context,
        "status": {
            "state": t.state,
            "message": {
                "messageId": format!("{}-said", t.id),
                "contextId": t.context,
                "taskId": t.id,
                "role": "ROLE_AGENT",
                "parts": [{ "text": t.says }],
            },
        },
    })
}

/// Where laye's app is given a session for its key (app/web/laye.js).
pub const APP_SESSION: &str = "/laye/session";

/// Where a node hands the reach a refused request lacked (QNTX server/out_of_reach.go).
pub const REACH_LACKED: &str = "/laye/pack/reach";

/// The reach a refused request lacked, as the node that refused it says.
#[derive(Deserialize)]
struct Lacked {
    node_did: String,
    #[serde(default)]
    node: String,
    path: String,
    to: String,
    asker_did: String,
    #[serde(default)]
    asker: String,
    person: String,
}

/// Puts what a refused request lacked into its person's pack.
async fn reach_lacked(
    inner: &Inner,
    keys: &passkeys::Passkeys,
    signer: &str,
    body: &Bytes,
) -> Response<Body> {
    let lacked = match serde_json::from_slice::<Lacked>(body) {
        Ok(l)
            if !l.path.is_empty()
                && !l.to.is_empty()
                && !l.asker_did.is_empty()
                && !l.person.is_empty() =>
        {
            l
        }
        Ok(_) => {
            return said(
                StatusCode::BAD_REQUEST,
                "path, to, asker_did and person are each named",
            );
        }
        Err(e) => {
            return said(
                StatusCode::BAD_REQUEST,
                format!("not what a refusal lacked: {e}"),
            );
        }
    };
    // A node speaks for its own refusals, and no other node's.
    if lacked.node_did != signer {
        return said(
            StatusCode::FORBIDDEN,
            format!("{signer} hands what {} refused", lacked.node_did),
        );
    }
    let held = collected::Collections {
        etcd: &keys.etcd,
        laye: &inner.did,
    };
    let node = if lacked.node.is_empty() {
        lacked.node_did.clone()
    } else {
        lacked.node
    };
    let asker = if lacked.asker.is_empty() {
        lacked.asker_did.clone()
    } else {
        lacked.asker
    };
    let reach = collected::Ask::Reach(collected::Reach {
        peer: lacked.node_did,
        path: lacked.path,
        to: lacked.to,
    });
    match held
        .lacked(
            &reach,
            &node,
            &lacked.asker_did,
            &asker,
            &lacked.person,
            now(),
        )
        .await
    {
        Ok(put) => json(
            StatusCode::OK,
            serde_json::json!({ "put": put }).to_string(),
        ),
        Err(why) => said(StatusCode::SERVICE_UNAVAILABLE, why),
    }
}

/// Where a node hands a key it holds nothing for (QNTX server/unknown_key.go).
pub const KEY_UNKNOWN: &str = "/laye/pack/admit";

/// A key a node holds nothing for, as the node says.
#[derive(Deserialize)]
struct Unknown {
    node_did: String,
    #[serde(default)]
    node: String,
    did: String,
    #[serde(default)]
    label: String,
    person: String,
}

/// Puts admitting a key into its node's ROOT's pack.
async fn key_unknown(
    inner: &Inner,
    keys: &passkeys::Passkeys,
    signer: &str,
    body: &Bytes,
) -> Response<Body> {
    let unknown = match serde_json::from_slice::<Unknown>(body) {
        Ok(u) if !u.did.is_empty() && !u.person.is_empty() => u,
        Ok(_) => return said(StatusCode::BAD_REQUEST, "did and person are each named"),
        Err(e) => {
            return said(
                StatusCode::BAD_REQUEST,
                format!("not a key a node holds nothing for: {e}"),
            );
        }
    };
    // A node speaks for its own keys, and no other node's.
    if unknown.node_did != signer {
        return said(
            StatusCode::FORBIDDEN,
            format!("{signer} hands what {} holds nothing for", unknown.node_did),
        );
    }
    let held = collected::Collections {
        etcd: &keys.etcd,
        laye: &inner.did,
    };
    let node = if unknown.node.is_empty() {
        unknown.node_did.clone()
    } else {
        unknown.node
    };
    let asker = if unknown.label.is_empty() {
        unknown.did.clone()
    } else {
        unknown.label.clone()
    };
    let admit = collected::Ask::Admit(collected::Admit {
        peer: unknown.node_did,
        did: unknown.did.clone(),
        label: unknown.label,
    });
    match held
        .lacked(&admit, &node, &unknown.did, &asker, &unknown.person, now())
        .await
    {
        Ok(put) => json(
            StatusCode::OK,
            serde_json::json!({ "put": put }).to_string(),
        ),
        Err(why) => said(StatusCode::SERVICE_UNAVAILABLE, why),
    }
}

/// Where QNTX hands what a person's connector said to a name.
pub const CONNECTOR_SAID: &str = "/laye/collected/said";

/// What QNTX hands laye of a connector's words.
#[derive(serde::Deserialize)]
struct ConnectorSaid {
    /// The name it was said to.
    to: String,
    /// The key of who it was said to, where QNTX names it: its Node Agent's,
    /// whose name is the node's to give.
    #[serde(default)]
    to_did: String,
    /// The person who sees what waits for QNTX's own agent.
    #[serde(default)]
    person: String,
    /// Said to QNTX's own agent: what is released goes to QNTX (hand_to_node).
    #[serde(default)]
    node: bool,
    /// Wakes nobody (QNTX collectedSaid.Quiet).
    #[serde(default)]
    quiet: bool,
    /// The connector's own key.
    from_did: String,
    /// Who it is, as QNTX names it.
    from: String,
    says: String,
    #[serde(default)]
    context: String,
}

/// Collects what a connector said to a name, and answers its Task.
async fn connector_said(inner: &Inner, keys: &passkeys::Passkeys, body: &Bytes) -> Response<Body> {
    let held = collected::Collections {
        etcd: &keys.etcd,
        laye: &inner.did,
    };
    let asked = match serde_json::from_slice::<ConnectorSaid>(body) {
        Ok(s) if !s.says.trim().is_empty() && !s.from_did.is_empty() => s,
        Ok(_) => {
            return said(
                StatusCode::BAD_REQUEST,
                "to, from_did and says are each named",
            );
        }
        Err(e) => {
            return said(
                StatusCode::BAD_REQUEST,
                format!("not what a connector said: {e}"),
            );
        }
    };
    let named_at = if asked.to_did.is_empty() {
        named(&keys.etcd, &asked.to).await
    } else {
        Ok(Some((asked.to_did.clone(), asked.to.clone())))
    };
    let (did, called) = match named_at {
        Ok(Some(held)) => held,
        Ok(None) => {
            return said(
                StatusCode::NOT_FOUND,
                format!("nobody holds the name {}", asked.to),
            );
        }
        Err(why) => return said(StatusCode::SERVICE_UNAVAILABLE, why),
    };
    let context = if asked.context.is_empty() {
        a2a::new_context_id()
    } else {
        asked.context
    };
    match held
        .collect(
            &did,
            &called,
            &asked.from_did,
            &asked.from,
            &asked.says,
            &[],
            &context,
            &collected::Whose {
                person: asked.person.clone(),
                node: asked.node,
                quiet: asked.quiet,
            },
            now(),
        )
        .await
    {
        Ok(task) => json(
            StatusCode::OK,
            serde_json::json!({ "task": task_json(&task) }).to_string(),
        ),
        Err(why) => said(StatusCode::SERVICE_UNAVAILABLE, why),
    }
}

/// What an agent says to a name, the Task it is, the row of the person asking,
/// and a delivery's whole: laye's, from what it keeps. None is not laye's to
/// answer, and goes on to QNTX.
async fn as_collections(
    inner: &Inner,
    keys: &passkeys::Passkeys,
    parts: &hyper::http::request::Parts,
    body: &Bytes,
    subject: &str,
    headers: &[(String, String)],
) -> Option<Response<Body>> {
    let held = collected::Collections {
        etcd: &keys.etcd,
        laye: &inner.did,
    };
    let path = parts.uri.path();
    let get = parts.method == hyper::Method::GET;
    let post = parts.method == hyper::Method::POST;
    let failed = |why: String| Some(said(StatusCode::SERVICE_UNAVAILABLE, why));

    if let Some((name, rest)) = at_a_name(path) {
        if post && rest == "message:send" {
            let (did, called) = match named(&keys.etcd, name).await {
                Ok(Some(held)) => held,
                Ok(None) => return None,
                Err(why) => return failed(why),
            };
            let Ok(send) = serde_json::from_slice::<a2a::SendMessageRequest>(body) else {
                return None;
            };
            let says: Vec<&str> = send
                .message
                .parts
                .iter()
                .filter_map(|p| p.as_text())
                .collect();
            if says.is_empty() {
                return Some(said(
                    StatusCode::BAD_REQUEST,
                    "what is said to a name crosses the row as text, and this said none",
                ));
            }
            let a2ui = match a2ui::messages_of(&send.message.parts) {
                Ok(a2ui) => a2ui,
                Err(why) => return Some(said(StatusCode::BAD_REQUEST, why)),
            };
            let from = match held.called(subject).await {
                Ok(called) => called,
                Err(why) => return failed(why),
            };
            let context = send
                .message
                .context_id
                .clone()
                .unwrap_or_else(a2a::new_context_id);
            return match held
                .collect(
                    &did,
                    &called,
                    subject,
                    &from,
                    &says.join("\n"),
                    &a2ui,
                    &context,
                    &collected::Whose::default(),
                    now(),
                )
                .await
            {
                Ok(task) => Some(json(
                    StatusCode::OK,
                    serde_json::json!({ "task": task_json(&task) }).to_string(),
                )),
                Err(why) => failed(why),
            };
        }
        if get && let Some(id) = rest.strip_prefix("tasks/") {
            return match held.task(id).await {
                Ok(Some(task)) => Some(json(StatusCode::OK, task_json(&task).to_string())),
                Ok(None) => None,
                Err(why) => failed(why),
            };
        }
        return None;
    }

    if get && let Some(id) = path.strip_prefix("/am/statusline/") {
        let person = held.person_of_key(subject).await.ok().flatten();
        return match held.detail(id, subject, person.as_deref()).await {
            Ok(Some(detail)) => Some(json(StatusCode::OK, detail.to_string())),
            Ok(None) => None,
            Err(why) => failed(why),
        };
    }

    if get && path == "/am/statusline" {
        let person = match held.person_of_key(subject).await {
            Ok(Some(person)) => person,
            Ok(None) => return None,
            Err(why) => return failed(why),
        };
        let items = match held.row(&person, now()).await {
            Ok(items) => items,
            Err(why) => return failed(why),
        };
        let query = issuer::form(parts.uri.query().unwrap_or_default());
        let format = query.get("format").map_or("", String::as_str).to_string();
        let full = parts
            .uri
            .path_and_query()
            .map_or(path, |p| p.as_str())
            .to_string();
        let qntx = match forward(
            inner,
            parts.version,
            &parts.method,
            &full,
            headers,
            Some(subject),
            Bytes::new(),
        )
        .await
        {
            Ok(resp) if resp.status() == StatusCode::OK => {
                resp.into_body().collect().await.ok().map(|b| b.to_bytes())
            }
            _ => None,
        };
        return Some(row_with(&format, qntx, &items));
    }
    None
}

/// QNTX's row with laye's items on it, or laye's alone when QNTX did not
/// answer: as JSON, or drawn as the row is (QNTX statusline renderLine).
fn row_with(format: &str, qntx: Option<Bytes>, items: &[serde_json::Value]) -> Response<Body> {
    if format == "json" {
        let mut row = qntx
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .unwrap_or_else(|| serde_json::json!({ "items": [], "deploys": [] }));
        if let Some(all) = row.get_mut("items").and_then(|i| i.as_array_mut()) {
            all.extend(items.iter().cloned());
        }
        return json(StatusCode::OK, row.to_string());
    }
    let mut line = qntx
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    for item in items {
        let text = |f: &str| {
            item.get(f)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        if !line.is_empty() {
            line.push_str("  ");
        }
        let drawn = format!(
            "{} {}",
            text("name"),
            text("note").replace(['\n', '#'], " ")
        );
        if format == "tmux" {
            line.push_str(&format!("#[range=user|{}]{drawn}#[norange]", text("id")));
        } else {
            line.push_str(&drawn);
        }
    }
    let mut resp = said(StatusCode::OK, line);
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

/// The request's headers as QNTX is handed them: a session's own signature
/// is laye's to read and goes no further; any other credential is QNTX's own.
fn passed_on(parts: &hyper::http::request::Parts) -> Vec<(String, String)> {
    parts
        .headers
        .iter()
        .filter(|(name, value)| {
            *name != hyper::header::AUTHORIZATION
                || !value.to_str().is_ok_and(|v| v.starts_with(SIGNED))
        })
        .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_string())))
        .collect()
}

fn is_grpc(parts: &hyper::http::request::Parts) -> bool {
    parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/grpc"))
}

/// QNTX not answering, as gRPC says it: UNAVAILABLE, in a response of
/// headers only (gRPC over HTTP/2, "Trailers-Only").
fn unavailable_over_grpc(why: &str) -> Response<Body> {
    let mut resp = Response::new(whole(Bytes::new()));
    let headers = resp.headers_mut();
    headers.insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/grpc"),
    );
    headers.insert("grpc-status", hyper::header::HeaderValue::from_static("14"));
    // Percent-encoded as gRPC says: what is not printable ASCII, and %.
    let message: String = format!("QNTX did not answer, and laye is still here: {why}")
        .bytes()
        .map(|b| match b {
            b' '..=b'~' if b != b'%' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect();
    if let Ok(message) = hyper::header::HeaderValue::from_str(&message) {
        headers.insert("grpc-message", message);
    }
    resp
}

fn is_the_card(parts: &hyper::http::request::Parts) -> bool {
    parts.method == hyper::Method::GET && parts.uri.path() == a2a_spoken::CARD_PATH
}

/// The public origin a request came to, by its host: the first laye takes
/// requests for when its host names none of them.
fn origin_of<'a>(inner: &'a Inner, parts: &hyper::http::request::Parts) -> &'a str {
    let host = parts
        .headers
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| parts.uri.authority().map(|a| a.as_str()))
        .unwrap_or_default();
    let origins = &inner.config.public_origins;
    origins
        .iter()
        .find(|origin| {
            origin
                .split_once("://")
                .is_some_and(|(_, name)| name == host)
        })
        .or_else(|| origins.first())
        .map_or("", String::as_str)
}

fn json(status: StatusCode, body: impl Into<Bytes>) -> Response<Body> {
    let mut resp = Response::new(whole(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    resp
}

/// An upgrade, asked of QNTX as this request was, and once QNTX switched,
/// what each side sends carried to the other until either closes.
async fn carry_upgrade(
    inner: &Inner,
    method: &hyper::Method,
    path: &str,
    headers: &[(String, String)],
    subject: Option<&str>,
    upgrading: hyper::upgrade::OnUpgrade,
) -> Response<Body> {
    let mut out = Request::builder()
        .method(method)
        .uri(format!("{}{path}", inner.config.qntx));
    for (name, value) in headers {
        out = out.header(name, value);
    }
    if let Some(subject) = subject {
        match carried(inner, subject) {
            Ok(signed) => out = out.header(hyper::header::AUTHORIZATION, signed),
            Err(why) => return said(StatusCode::INTERNAL_SERVER_ERROR, why),
        }
    }
    let out = match out.body(Full::new(Bytes::new())) {
        Ok(out) => out,
        Err(e) => return said(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let mut resp = match inner.client.request(out).await {
        Ok(resp) => resp,
        Err(e) => {
            return said(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("QNTX did not answer, and laye is still here: {e}"),
            );
        }
    };
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        let (parts, body) = resp.into_parts();
        let body = body
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        return Response::from_parts(parts, whole(body));
    }
    let switched = hyper::upgrade::on(&mut resp);
    tokio::spawn(async move {
        match tokio::try_join!(upgrading, switched) {
            Ok((page, qntx)) => {
                let (mut page, mut qntx) = (TokioIo::new(page), TokioIo::new(qntx));
                if let Err(e) = tokio::io::copy_bidirectional(&mut page, &mut qntx).await {
                    eprintln!("laye-front: a carried socket ended: {e}");
                }
            }
            Err(e) => eprintln!("laye-front: a socket did not switch: {e}"),
        }
    });
    let mut switching = Response::new(whole(Bytes::new()));
    *switching.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    *switching.headers_mut() = resp.headers().clone();
    switching
}

/// The session a signature is: its own key, for this origin, short-lived, and
/// presented once. Else why not.
fn who_signed(inner: &Inner, token: &str) -> Result<String, String> {
    let claims = jwt::read(token).map_err(|e| format!("the signature does not verify: {e}"))?;
    if claims.sub != claims.iss {
        return Err(format!(
            "{} signed for {}, and laye takes a key signing as itself",
            claims.iss, claims.sub
        ));
    }
    let for_here = claims
        .aud
        .iter()
        .any(|aud| inner.config.public_origins.contains(aud));
    if !for_here {
        return Err(format!(
            "the signature is for {:?}, and this is {:?}",
            claims.aud, inner.config.public_origins
        ));
    }
    let now = now();
    if claims.exp <= now {
        return Err(format!("the signature ended at {}", claims.exp));
    }
    if claims.exp > now + MAX_LIFE {
        return Err(format!(
            "the signature lasts past the {MAX_LIFE} seconds one may"
        ));
    }
    let id_ok = claims.jti.len() == 32 && claims.jti.bytes().all(|b| b.is_ascii_hexdigit());
    if !id_ok {
        return Err(format!(
            "the signature's jti {:?} is not 16 bytes in hex",
            claims.jti
        ));
    }
    let mut seen = inner.seen.lock().unwrap_or_else(|p| p.into_inner());
    seen.retain(|_, until| *until > now);
    if seen.insert(claims.jti.clone(), claims.exp).is_some() {
        return Err(format!(
            "the signature {} was already presented",
            claims.jti
        ));
    }
    Ok(claims.iss)
}

/// "A mail actually goes out to both me and my friend"
/// An invitation laye just made, mailed by QNTX when it names an address.
/// The invitation stands either way; the answer says whether it was mailed.
async fn mailed(inner: &Inner, answered: Response<Body>) -> Response<Body> {
    let made = match answered.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return said(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let Ok(inv) = serde_json::from_slice::<invitations::Invitation>(&made) else {
        return json(StatusCode::OK, made);
    };
    let mut told = serde_json::json!(inv);
    if let Some(asked) = mail::invited(&inv, &inner.config.issuer)
        && let Some(fields) = told.as_object_mut()
    {
        match mail::send(inner, asked).await {
            Ok(()) => fields.insert("mailed".into(), serde_json::json!(inv.email)),
            Err(why) => {
                eprintln!("laye-front: invitation {} was not mailed: {why}", inv.id);
                fields.insert("mail_error".into(), serde_json::json!(why))
            }
        };
    }
    json(StatusCode::OK, told.to_string())
}

/// laye's own signature, naming the session, for QNTX alone and one request.
fn carried(inner: &Inner, subject: &str) -> Result<String, String> {
    let now = now();
    jwt::sign(
        &inner.key,
        &jwt::Claims {
            iss: inner.did.clone(),
            sub: subject.to_string(),
            aud: vec![inner.config.qntx_did.clone()],
            exp: now + CARRIED_LIFE,
            iat: now,
            jti: jwt::fresh_jti(),
            label: "laye".into(),
        },
    )
    .map(|signed| format!("{SIGNED}{signed}"))
    .map_err(|e| e.to_string())
}

/// The request, handed to QNTX. Err is QNTX not answering at all.
async fn forward(
    inner: &Inner,
    version: hyper::Version,
    method: &hyper::Method,
    path: &str,
    headers: &[(String, String)],
    subject: Option<&str>,
    body: Bytes,
) -> Result<Response<Body>, String> {
    let mut out = Request::builder()
        .method(method)
        .uri(format!("{}{path}", inner.config.qntx));
    for (name, value) in headers {
        out = out.header(name, value);
    }
    if let Some(subject) = subject {
        let signed = carried(inner, subject)?;
        out = out.header(hyper::header::AUTHORIZATION, signed);
    }
    let out = out.body(Full::new(body)).map_err(|e| e.to_string())?;
    // gRPC is HTTP/2, however it reached laye: a front door that ended TLS
    // hands it on in HTTP/1.1 (Caddy's reverse_proxy does), and QNTX's gRPC
    // refuses that ("gRPC requires HTTP/2").
    let grpc = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type") && value.starts_with("application/grpc")
    });
    let client = if version == hyper::Version::HTTP_2 || grpc {
        &inner.h2c
    } else {
        &inner.client
    };
    let resp = client.request(out).await.map_err(|e| e.to_string())?;
    // QNTX's answer goes on as it comes: a stream of live output is not held
    // back until it ends.
    Ok(resp.map(BodyExt::boxed))
}

/// What laye answers with: QNTX's answer as it streams, or laye's own words.
pub(crate) type Body = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn whole(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

/// What was said while QNTX did not answer, kept, and answered as a Task that
/// has not been received yet, in the version and binding it was said in.
fn keep(
    inner: &Inner,
    path: String,
    headers: Vec<(String, String)>,
    subject: String,
    body: &Bytes,
    send: &a2a_spoken::Send,
) -> Response<Body> {
    let held = Held {
        path,
        headers,
        body: B64.encode(body),
        subject,
    };
    match hold(inner, held) {
        Ok(kept) => {
            let id = format!("laye-held-{}-{kept}", now());
            json(StatusCode::OK, a2a_spoken::submitted(send, &id))
        }
        Err(why) => said(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("QNTX did not answer, and laye could not keep what was said: {why}"),
        ),
    }
}

/// `held`, kept until QNTX is handed it; how many are kept with it.
fn hold(inner: &Inner, held: Held) -> Result<usize, String> {
    let mut all = inner.held.lock().unwrap_or_else(|p| p.into_inner());
    all.push(held);
    if let Err(why) = save(&inner.config.held_at, &all) {
        all.pop();
        return Err(why);
    }
    Ok(all.len())
}

/// What was kept, handed to QNTX in the order it was said, until QNTX does
/// not answer.
async fn hand_over(inner: &Inner) {
    loop {
        let first = {
            let all = inner.held.lock().unwrap_or_else(|p| p.into_inner());
            match all.first() {
                Some(first) => first.clone(),
                None => return,
            }
        };
        let Ok(body) = B64.decode(&first.body) else {
            eprintln!("laye-front: a kept request's body does not read; it is dropped");
            drop_first(inner);
            continue;
        };
        let handed = forward(
            inner,
            hyper::Version::HTTP_11,
            &hyper::Method::POST,
            &first.path,
            &first.headers,
            Some(&first.subject),
            Bytes::from(body),
        )
        .await;
        match handed {
            Ok(resp) => {
                eprintln!(
                    "laye-front: handed over {} for {}: QNTX answered {}",
                    first.path,
                    first.subject,
                    resp.status()
                );
                drop_first(inner);
            }
            Err(_) => return,
        }
    }
}

fn drop_first(inner: &Inner) {
    let mut all = inner.held.lock().unwrap_or_else(|p| p.into_inner());
    if !all.is_empty() {
        all.remove(0);
    }
    if let Err(why) = save(&inner.config.held_at, &all) {
        eprintln!("laye-front: what is kept was not written: {why}");
    }
}

fn load(path: &std::path::Path) -> Result<Vec<Held>, Box<Error>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(laye_peer::error(
                "held",
                "what laye kept does not read",
                format!("{}: {e}", path.display()),
            ));
        }
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|e| {
                laye_peer::error(
                    "held",
                    "a request laye kept does not read",
                    format!("{}: {e}", path.display()),
                )
            })
        })
        .collect()
}

/// All that is kept, written whole beside the file and moved over it.
fn save(path: &std::path::Path, all: &[Held]) -> Result<(), String> {
    let mut text = String::new();
    for held in all {
        text.push_str(&serde_json::to_string(held).map_err(|e| e.to_string())?);
        text.push('\n');
    }
    write_whole(path, text.as_bytes())
}

/// `bytes`, written beside `path` and moved over it.
fn write_whole(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let mut beside = path.as_os_str().to_owned();
    beside.push(".new");
    std::fs::write(&beside, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::rename(&beside, path).map_err(|e| format!("{}: {e}", path.display()))
}
