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

pub mod door;
pub mod invitations;
mod issuer;
pub mod jwt;

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
    /// Signatures presented, by id, until they expire: each is spent once.
    seen: Mutex<HashMap<String, u64>>,
    held: Mutex<Vec<Held>>,
    issued: issuer::Issued,
    invitations: invitations::Invitations,
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
    let inner = Arc::new(Inner {
        config,
        key,
        did: did.clone(),
        client: Client::builder(TokioExecutor::new()).build_http(),
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
                        if let Err(e) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
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

/// What laye answers itself, at its own name: where people log in. Anything
/// else, and every other name, goes on to QNTX.
fn as_laye(
    inner: &Inner,
    parts: &hyper::http::request::Parts,
    body: &[u8],
) -> Option<Response<Full<Bytes>>> {
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
    let laye = issuer::Laye {
        issuer: &inner.config.issuer,
        did: &inner.did,
        nodes: &inner.config.nodes,
        roots: &inner.config.root_identities,
        signers: &inner.config.binding_signers,
        issued: &inner.issued,
        invitations: &inner.invitations,
        now: now(),
    };
    let get = parts.method == hyper::Method::GET;
    let post = parts.method == hyper::Method::POST;
    let (status, kind, text) = match parts.uri.path() {
        "/.well-known/oauth-authorization-server" if get => laye.metadata(),
        "/auth/authorize" if get => laye.authorize(parts.uri.query().unwrap_or_default()),
        "/laye/challenge" if get => laye.challenge(),
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

fn said(status: StatusCode, words: impl Into<String>) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from(words.into())));
    *resp.status_mut() = status;
    resp
}

async fn answer(inner: &Inner, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
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

    if let Some(answered) = as_laye(inner, &parts, &body) {
        return answered;
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

    // laye decides who logs in. QNTX hears only of a login laye admitted.
    if parts.method == hyper::Method::POST && parts.uri.path() == "/auth/laye/verify" {
        let login: door::Login = match serde_json::from_slice(&body) {
            Ok(login) => login,
            Err(e) => {
                return said(
                    StatusCode::BAD_REQUEST,
                    format!("the login does not read: {e}"),
                );
            }
        };
        if let Err(why) = door::admitted_as(
            &login,
            &inner.config.root_identities,
            &inner.config.binding_signers,
        ) {
            return said(StatusCode::FORBIDDEN, why);
        }
    }

    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter(|(name, _)| *name != hyper::header::AUTHORIZATION)
        .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_string())))
        .collect();

    match forward(
        inner,
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
            let is_a_send = parts.method == hyper::Method::POST
                && path.starts_with("/a2a/")
                && path.ends_with("/message:send");
            match subject {
                Some(subject) if is_a_send => keep(inner, path, headers, subject, &body),
                _ => said(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("QNTX did not answer, and laye is still here: {why}"),
                ),
            }
        }
    }
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
    method: &hyper::Method,
    path: &str,
    headers: &[(String, String)],
    subject: Option<&str>,
    body: Bytes,
) -> Result<Response<Full<Bytes>>, String> {
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
    let resp = inner.client.request(out).await.map_err(|e| e.to_string())?;
    let (parts, body) = resp.into_parts();
    let body = body
        .collect()
        .await
        .map_err(|e| format!("QNTX's answer did not arrive whole: {e}"))?
        .to_bytes();
    Ok(Response::from_parts(parts, Full::new(body)))
}

/// What was said while QNTX did not answer, kept, and answered as a Task that
/// has not been received yet.
fn keep(
    inner: &Inner,
    path: String,
    headers: Vec<(String, String)>,
    subject: String,
    body: &Bytes,
) -> Response<Full<Bytes>> {
    let held = Held {
        path,
        headers,
        body: B64.encode(body),
        subject,
    };
    let mut all = inner.held.lock().unwrap_or_else(|p| p.into_inner());
    all.push(held);
    if let Err(why) = save(&inner.config.held_at, &all) {
        all.pop();
        return said(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("QNTX did not answer, and laye could not keep what was said: {why}"),
        );
    }
    let id = format!("laye-held-{}-{}", now(), all.len());
    said(
        StatusCode::OK,
        serde_json::json!({
            "task": { "id": id, "status": { "state": "TASK_STATE_SUBMITTED" } }
        })
        .to_string(),
    )
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
    let mut beside = path.as_os_str().to_owned();
    beside.push(".new");
    std::fs::write(&beside, text).map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::rename(&beside, path).map_err(|e| format!("{}: {e}", path.display()))
}
