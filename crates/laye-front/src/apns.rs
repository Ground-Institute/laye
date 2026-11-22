//! "laye should get it's own island as well"
//!
//! laye reaches the island of laye's own app through Apple: it starts a Live
//! Activity on a phone with the app closed, moves it, and ends it. The key is
//! the team's APNs key, the topic laye's app.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::pkcs8::DecodePrivateKey;
use serde::Deserialize;
use tokio::sync::Mutex;

/// Apple's host for an app installed from TestFlight or the App Store.
pub const PRODUCTION: &str = "api.push.apple.com";
/// Apple's host for an app built for development.
pub const DEVELOPMENT: &str = "api.sandbox.push.apple.com";

/// What laye.toml names of Apple: laye's app, the team, the key and where it is.
#[derive(Clone, Debug, Deserialize)]
pub struct ApnsAt {
    /// laye's app, which is the topic.
    pub bundle_id: String,
    pub team_id: String,
    pub key_id: String,
    /// The .p8 as Apple gave it.
    pub key: std::path::PathBuf,
    #[serde(default)]
    pub development: bool,
}

/// One thing said to a Live Activity.
pub struct Said {
    /// The phone's token to start by, or the activity's own to move or end it.
    pub token: String,
    /// "start", "update" or "end".
    pub event: &'static str,
    /// What it shows.
    pub state: serde_json::Value,
    /// On start: its type, and what never changes while it stands.
    pub attributes: Option<(&'static str, serde_json::Value)>,
    /// On start: the alert that lights the phone.
    pub alert: Option<(String, String)>,
    /// Seconds since 1970: when it is stale, and, on end, when it leaves.
    pub stale: u64,
    pub dismissal: u64,
}

/// Why Apple did not take what was said.
#[derive(Debug)]
pub struct Refused {
    pub status: u16,
    pub reason: String,
}

impl Refused {
    /// The token is of an app that is no longer on that phone, or of an
    /// activity that ended: nothing is said to it again.
    pub fn gone(&self) -> bool {
        self.status == 410 || self.reason == "BadDeviceToken" || self.reason == "Unregistered"
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Apple answered {}: {}", self.status, self.reason)
    }
}

/// laye's sender to Apple.
pub struct Apns {
    at: ApnsAt,
    key: SigningKey,
    /// The bearer and when it was made: Apple takes one for an hour and
    /// refuses one renewed more than once in twenty minutes.
    bearer: Mutex<Option<(String, u64)>>,
    tls: tokio_rustls::TlsConnector,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Apns {
    /// The sender for what laye.toml names, the key read from where it says.
    pub fn new(at: ApnsAt) -> Result<Self, String> {
        let pem = std::fs::read_to_string(&at.key)
            .map_err(|e| format!("the APNs key at {} does not read: {e}", at.key.display()))?;
        let key = SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| format!("the APNs key at {} is no P-256 key: {e}", at.key.display()))?;
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS for Apple was not set up: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self {
            at,
            key,
            bearer: Mutex::new(None),
            tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
        })
    }

    fn host(&self) -> &'static str {
        if self.at.development {
            DEVELOPMENT
        } else {
            PRODUCTION
        }
    }

    async fn bearer(&self) -> String {
        let mut held = self.bearer.lock().await;
        let t = now();
        if let Some((bearer, made)) = held.as_ref()
            && t < made + 40 * 60
        {
            return bearer.clone();
        }
        let b64 = |v: &serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
        };
        let input = format!(
            "{}.{}",
            b64(&serde_json::json!({ "alg": "ES256", "kid": self.at.key_id })),
            b64(&serde_json::json!({ "iss": self.at.team_id, "iat": t }))
        );
        let signature: Signature = self.key.sign(input.as_bytes());
        let bearer = format!(
            "{input}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        *held = Some((bearer.clone(), t));
        bearer
    }

    /// The body Apple takes for what is said.
    pub fn body(said: &Said) -> serde_json::Value {
        let mut aps = serde_json::Map::new();
        aps.insert("timestamp".into(), now().into());
        aps.insert("event".into(), said.event.into());
        aps.insert("content-state".into(), said.state.clone());
        if said.stale > 0 {
            aps.insert("stale-date".into(), said.stale.into());
        }
        if said.dismissal > 0 {
            aps.insert("dismissal-date".into(), said.dismissal.into());
        }
        if let Some((kind, attributes)) = &said.attributes {
            aps.insert("attributes-type".into(), (*kind).into());
            aps.insert("attributes".into(), attributes.clone());
        }
        if let Some((title, body)) = &said.alert {
            aps.insert(
                "alert".into(),
                serde_json::json!({ "title": title, "body": body }),
            );
        }
        serde_json::json!({ "aps": aps })
    }

    /// Says one thing to a Live Activity. Apple's own id for it, or why not.
    pub async fn say(&self, said: &Said) -> Result<String, Result<Refused, String>> {
        let host = self.host();
        let tcp = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect((host, 443)),
        )
        .await
        .map_err(|elapsed| Err(format!("{host} was not reached: {elapsed}")))?
        .map_err(|e| Err(format!("{host} was not reached: {e}")))?;
        let name = rustls::pki_types::ServerName::try_from(host)
            .map_err(|e| Err(format!("{host} is no name: {e}")))?;
        let tls = self
            .tls
            .connect(name, tcp)
            .await
            .map_err(|e| Err(format!("TLS with {host} did not begin: {e}")))?;
        let (mut sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(tls),
        )
        .await
        .map_err(|e| Err(format!("HTTP/2 with {host} did not begin: {e}")))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("laye-front: the connection to Apple ended: {e}");
            }
        });
        let request = hyper::Request::post(format!("https://{host}/3/device/{}", said.token))
            .header("authorization", format!("bearer {}", self.bearer().await))
            .header(
                "apns-topic",
                format!("{}.push-type.liveactivity", self.at.bundle_id),
            )
            .header("apns-push-type", "liveactivity")
            .header("apns-priority", "10")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(Self::body(said).to_string())))
            .map_err(|e| Err(format!("the request to Apple was not made: {e}")))?;
        let answered = tokio::time::timeout(Duration::from_secs(10), sender.send_request(request))
            .await
            .map_err(|elapsed| Err(format!("{host} did not answer: {elapsed}")))?
            .map_err(|e| Err(format!("{host} did not answer: {e}")))?;
        let status = answered.status().as_u16();
        let id = answered
            .headers()
            .get("apns-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if status == 200 {
            return Ok(id);
        }
        let body = answered
            .into_body()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        let reason = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
            .unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned());
        Err(Ok(Refused { status, reason }))
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn what_starts_one_carries_its_type_and_what_never_changes() {
        let body = Apns::body(&Said {
            token: "ab".into(),
            event: "start",
            state: serde_json::json!({ "says": "1 waits" }),
            attributes: Some((
                "WaitsAttributes",
                serde_json::json!({ "waits": "laye/collected/did:key:z" }),
            )),
            alert: Some(("1 waits for Cumulus".into(), "ChatGPT: hello".into())),
            stale: 10,
            dismissal: 0,
        });
        let aps = &body["aps"];
        assert_eq!(aps["event"], "start");
        assert_eq!(aps["attributes-type"], "WaitsAttributes");
        assert_eq!(aps["attributes"]["waits"], "laye/collected/did:key:z");
        assert_eq!(aps["content-state"]["says"], "1 waits");
        assert_eq!(aps["alert"]["title"], "1 waits for Cumulus");
        assert_eq!(aps["stale-date"], 10);
        assert!(aps.get("dismissal-date").is_none());
    }
}
