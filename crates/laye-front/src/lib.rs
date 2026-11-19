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
pub mod devices;
pub mod door;
pub mod etcd;
pub mod invitations;
mod issuer;
pub mod jwt;
pub mod names;
pub mod passkeys;

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
}

/// Where names are kept, and whose key admits a session's.
#[derive(Clone, Debug, Deserialize)]
pub struct NamesAt {
    /// etcd, as its clients reach it: http://127.0.0.1:2379.
    pub etcd: String,
    /// The did:keys whose signature admits a session's key.
    pub admitters: Vec<String>,
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
    let names = config.names.as_ref().map(|at| names::Names {
        etcd: etcd::Etcd::new(&at.etcd, client.clone()),
        admitters: at.admitters.clone(),
    });
    let passkeys = match (&config.passkeys, &config.names) {
        (Some(at), Some(names)) => Some(passkeys::Passkeys::new(
            etcd::Etcd::new(&names.etcd, client.clone()),
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
    let inner = Arc::new(Inner {
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
    });
    let run = tokio::spawn(async move {
        let mut tick = tokio::time::interval(RETRY);
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
                _ = tick.tick() => hand_over(&inner).await,
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
        "/laye/challenge" if get => {
            let (status, _, text) = laye_of(inner).challenge();
            return Some(json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                text,
            ));
        }
        "/laye/passkey/me" if get => match person_asking(inner, parts) {
            Ok((person, level)) => passkeys::Answer {
                status: 200,
                body: serde_json::json!({ "person": person, "level": level }),
                session: None,
            },
            Err(why) => passkeys::Answer {
                status: 401,
                body: serde_json::json!({ "error": why }),
                session: None,
            },
        },
        "/laye/passkey/enrol/begin" if post => match serde_json::from_slice::<door::Login>(body) {
            Ok(login) => match laye_of(inner).first_half(&login) {
                Ok(first) => keys.enrol_begin(first, now()),
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
        "/laye/passkey/signin/begin" if post => keys.sign_in_begin(now()),
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
        );
    let mut resp = said(StatusCode::OK, page);
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

/// laye's wasm and the JS that loads it, from laye-web.
fn web_file(inner: &Inner, file: &str) -> Response<Body> {
    let kind = match file {
        "laye_p2p.js" => "text/javascript",
        "laye_p2p_bg.wasm" => "application/wasm",
        _ => {
            return said(
                StatusCode::NOT_FOUND,
                "laye serves its wasm and its JS, and nothing else here",
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
    let host = parts
        .headers
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let ours = inner
        .config
        .issuer
        .split_once("://")
        .is_some_and(|(_, name)| name.trim_end_matches('/') == host);
    if !ours {
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
            let signer = match signer_of(inner, parts) {
                Ok(signer) => signer,
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
    let mut resp = said(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        text,
    );
    if let Ok(kind) = hyper::header::HeaderValue::from_str(kind) {
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, kind);
    }
    Some(resp)
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

async fn answer(inner: &Inner, mut req: Request<hyper::body::Incoming>) -> Response<Body> {
    // A request asking to upgrade (QNTX's page's WebSocket) is carried
    // through once both sides have switched.
    let upgrading = req
        .headers()
        .contains_key(hyper::header::UPGRADE)
        .then(|| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
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

    if let Some(answered) = as_laye(inner, &parts, &body) {
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
