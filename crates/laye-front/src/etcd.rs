//! etcd, as laye asks it: through its JSON gateway (`/v3/...`), with keys and
//! values in base64, over the HTTP client laye already holds.

// "Isn't it covered by using etcd ?"
// "I'd put names under /names/ there from the start,"
// "all right"

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use serde_json::{Value, json};

pub struct Etcd {
    /// Where etcd answers its clients: http://127.0.0.1:2379.
    at: String,
    client: Client<HttpConnector, Full<Bytes>>,
}

/// A key's value, and the revision it was last written at.
pub struct Kv {
    pub value: Vec<u8>,
    pub mod_revision: i64,
}

/// One thing a transaction does when every comparison holds.
pub enum Op {
    Put(String, Vec<u8>),
    Delete(String),
}

impl Etcd {
    pub fn new(at: &str, client: Client<HttpConnector, Full<Bytes>>) -> Self {
        Etcd {
            at: at.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// The key's value, or None when nothing is kept at it.
    pub async fn get(&self, key: &str) -> Result<Option<Kv>, String> {
        let answer = self
            .ask("/v3/kv/range", json!({ "key": B64.encode(key) }))
            .await?;
        let Some(kv) = answer
            .get("kvs")
            .and_then(Value::as_array)
            .and_then(|kvs| kvs.first())
        else {
            return Ok(None);
        };
        let value = kv
            .get("value")
            .and_then(Value::as_str)
            .map(|v| B64.decode(v))
            .transpose()
            .map_err(|e| format!("etcd's value at {key} is not base64: {e}"))?
            .unwrap_or_default();
        Ok(Some(Kv {
            value,
            mod_revision: revision(kv.get("mod_revision")),
        }))
    }

    /// The ops, done together, only when each key is still at the revision it
    /// was read at: 0 for a key nothing is kept at. Whether they were done.
    pub async fn txn(&self, unchanged: &[(&str, i64)], ops: Vec<Op>) -> Result<bool, String> {
        let compare: Vec<Value> = unchanged
            .iter()
            .map(|(key, at)| {
                json!({
                    "key": B64.encode(key),
                    "target": "MOD",
                    "result": "EQUAL",
                    "mod_revision": at.to_string(),
                })
            })
            .collect();
        let success: Vec<Value> = ops
            .into_iter()
            .map(|op| match op {
                Op::Put(key, value) => json!({
                    "request_put": { "key": B64.encode(key), "value": B64.encode(value) }
                }),
                Op::Delete(key) => json!({
                    "request_delete_range": { "key": B64.encode(key) }
                }),
            })
            .collect();
        let answer = self
            .ask(
                "/v3/kv/txn",
                json!({ "compare": compare, "success": success }),
            )
            .await?;
        // The gateway leaves out a field that is false.
        Ok(answer.get("succeeded").and_then(Value::as_bool) == Some(true))
    }

    async fn ask(&self, path: &str, body: Value) -> Result<Value, String> {
        let url = format!("{}{path}", self.at);
        let request = Request::post(&url)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|e| e.to_string())?;
        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| format!("etcd at {} did not answer: {e}", self.at))?;
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("etcd's answer at {url} did not arrive: {e}"))?
            .to_bytes();
        if !status.is_success() {
            return Err(format!(
                "etcd at {url} answered {status}: {}",
                String::from_utf8_lossy(&bytes)
            ));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| format!("etcd's answer at {url} is not JSON: {e}"))
    }
}

/// A revision as the gateway writes it: a string of digits, or left out for 0.
fn revision(field: Option<&Value>) -> i64 {
    match field {
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        _ => 0,
    }
}
