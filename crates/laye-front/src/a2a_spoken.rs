//! A2A while QNTX is down: laye answers in every version QNTX's card says it
//! speaks, where the card says each is reached.

// "do we support 0.3 yes or not, if not, make it support it, period"
// "laye would help us still be A2A capable, even when QNTX is down"
// "For the 0.3 rows, laye either answers 0.3 itself,"
// "sure, this is fine"
//
// 1.0 is a2a-rs's, pinned: the A2A version QNTX speaks through a2a-go. a2a-rs
// has no 0.3, so laye says 0.3 itself, as a2a-go's a2av0 says it.

use std::path::Path;

use a2a::{
    AgentInterface, JsonRpcId, JsonRpcRequest, JsonRpcResponse, SendMessageRequest,
    SendMessageResponse, TRANSPORT_PROTOCOL_HTTP_JSON, TRANSPORT_PROTOCOL_JSONRPC, Task, TaskState,
    TaskStatus,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// Where a card is served (A2A §8.2).
pub const CARD_PATH: &str = "/.well-known/agent-card.json";

/// The 1.0 HTTP+JSON send, beneath the interface, or beneath a tenant there
/// (a2a-rs a2a-server/src/rest.rs REST_SEND_MESSAGE_PATH).
const SEND_10_REST: &str = "/message:send";

/// The 0.3 HTTP+JSON send, beneath the interface (a2a-go a2av0
/// RESTPathPrefix + SendMessage).
const SEND_03_REST: &str = "/v1/message:send";

/// The 0.3 JSON-RPC send (a2a-go a2alegacy MethodMessageSend).
const SEND_03_RPC: &str = "message/send";

/// A send laye answers in place of QNTX: the version and binding it arrived
/// in, and what its answer carries.
#[derive(Debug, PartialEq)]
pub struct Send {
    pub version: String,
    pub binding: String,
    /// The JSON-RPC request's id, answered under the same.
    rpc: Option<JsonRpcId>,
    context: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Card {
    #[serde(default)]
    supported_interfaces: Vec<AgentInterface>,
}

/// The interfaces of the card kept at `at`, the longest path first: a path
/// beneath two is the deeper one's. None when no card is kept.
fn interfaces(at: &Path) -> Vec<(String, AgentInterface)> {
    let Ok(bytes) = std::fs::read(at) else {
        return Vec::new();
    };
    let Ok(card) = serde_json::from_slice::<Card>(&bytes) else {
        return Vec::new();
    };
    let mut at: Vec<(String, AgentInterface)> = card
        .supported_interfaces
        .into_iter()
        .filter_map(|i| Some((path_of(&i.url)?, i)))
        .collect();
    at.sort_by_key(|(path, _)| std::cmp::Reverse(path.len()));
    at
}

/// The path of a URL: what follows its scheme and host, without a trailing /.
fn path_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let path = rest.find('/').and_then(|at| rest.get(at..)).unwrap_or("");
    Some(path.trim_end_matches('/').to_string())
}

/// What `path` is beneath `at`: empty when it is `at`. None when it is not
/// beneath it.
fn beneath<'a>(path: &'a str, at: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(at)?;
    (rest.is_empty() || rest.starts_with('/')).then_some(rest)
}

/// The send a POST to `path` is, in the first interface of the kept card that
/// takes it. None is no send any interface takes.
pub fn send_of(card_at: &Path, path: &str, body: &[u8]) -> Option<Send> {
    let path = path.split_once('?').map_or(path, |(p, _)| p);
    let body: Value = serde_json::from_slice(body).ok()?;
    interfaces(card_at).into_iter().find_map(|(at, i)| {
        let context = taken(
            &i.protocol_version,
            &i.protocol_binding,
            beneath(path, &at)?,
            &body,
        )?;
        let rpc = if i.protocol_binding == TRANSPORT_PROTOCOL_JSONRPC {
            Some(body.get("id").cloned().unwrap_or(Value::Null))
                .and_then(|id| serde_json::from_value::<JsonRpcId>(id).ok())
        } else {
            None
        };
        Some(Send {
            version: i.protocol_version,
            binding: i.protocol_binding,
            rpc,
            context: context.unwrap_or_else(a2a::new_context_id),
        })
    })
}

/// Whether `body`, POSTed `beneath` an interface of `version` over `binding`,
/// is a send there, and the context its message names.
fn taken(version: &str, binding: &str, beneath: &str, body: &Value) -> Option<Option<String>> {
    match (version, binding) {
        (a2a::VERSION, TRANSPORT_PROTOCOL_HTTP_JSON) => {
            // At no tenant, or beneath one: a single segment.
            let tenant = beneath.strip_suffix(SEND_10_REST)?;
            if tenant.matches('/').count() > 1 {
                return None;
            }
            let send = serde_json::from_value::<SendMessageRequest>(body.clone()).ok()?;
            Some(send.message.context_id)
        }
        (a2a::VERSION, TRANSPORT_PROTOCOL_JSONRPC) => {
            let rpc = serde_json::from_value::<JsonRpcRequest>(body.clone()).ok()?;
            if !beneath.is_empty() || rpc.method != a2a::methods::SEND_MESSAGE {
                return None;
            }
            let send = serde_json::from_value::<SendMessageRequest>(rpc.params?).ok()?;
            Some(send.message.context_id)
        }
        ("0.3", TRANSPORT_PROTOCOL_HTTP_JSON) => {
            if beneath != SEND_03_REST {
                return None;
            }
            Some(context_in(body.get("message")?))
        }
        ("0.3", TRANSPORT_PROTOCOL_JSONRPC) => {
            if !beneath.is_empty() || body.get("method")?.as_str()? != SEND_03_RPC {
                return None;
            }
            Some(context_in(body.get("params")?.get("message")?))
        }
        _ => None,
    }
}

fn context_in(message: &Value) -> Option<String> {
    message.get("contextId")?.as_str().map(str::to_string)
}

/// The answer to `send`: a Task submitted under `id`, in its version over its
/// binding.
pub fn submitted(send: &Send, id: &str) -> String {
    let rpc = |result: Value| {
        serde_json::to_string(&JsonRpcResponse::success(
            send.rpc.clone().unwrap_or(JsonRpcId::Null),
            result,
        ))
        .unwrap_or_default()
    };
    match (send.version.as_str(), send.binding.as_str()) {
        (a2a::VERSION, binding) => {
            let task = SendMessageResponse::Task(Task {
                id: id.to_string(),
                context_id: send.context.clone(),
                status: TaskStatus {
                    state: TaskState::Submitted,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            });
            let task = serde_json::to_value(&task).unwrap_or_default();
            if binding == TRANSPORT_PROTOCOL_JSONRPC {
                rpc(task)
            } else {
                task.to_string()
            }
        }
        // a2a-go a2apb/v0/pbjson ToProtoSendMessageResult: the Task in a
        // SendMessageResponse, as ProtoJSON.
        (_, TRANSPORT_PROTOCOL_HTTP_JSON) => json!({
            "task": {
                "id": id,
                "contextId": send.context,
                "status": { "state": "TASK_STATE_SUBMITTED" }
            }
        })
        .to_string(),
        // a2a-go a2alegacy Task.MarshalJSON: the Task itself, of kind task.
        _ => rpc(json!({
            "kind": "task",
            "id": id,
            "contextId": send.context,
            "status": { "state": "submitted" }
        })),
    }
}
