//! A2A at laye: every version laye speaks is a row, where its path says, and
//! laye's own card names each.

// "do we support 0.3 yes or not, if not, make it support it, period"
// "laye would help us still be A2A capable, even when QNTX is down"
// "For the 0.3 rows, laye either answers 0.3 itself,"
// "sure, this is fine"
// "for agents"
// "talkign to agents"
// "laye is foundational, while QNTX can remain to be doing experimental things"
//
// 1.0 is a2a-rs's, pinned: the A2A version QNTX speaks through a2a-go. a2a-rs
// has no 0.3, so laye says 0.3 itself, as a2a-go's a2av0 says it.

use a2a::{
    JsonRpcId, JsonRpcRequest, JsonRpcResponse, SendMessageRequest, SendMessageResponse,
    TRANSPORT_PROTOCOL_HTTP_JSON, TRANSPORT_PROTOCOL_JSONRPC, Task, TaskState, TaskStatus,
};
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

/// One A2A version laye speaks: where its bindings are reached, and which.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Spoken {
    pub version: &'static str,
    pub base: &'static str,
    pub bindings: &'static [&'static str],
}

/// Every A2A version laye speaks, the newest first: the order its card lists
/// them in. Where a request arrives is the version it is in.
pub const SPOKEN: &[Spoken] = &[
    Spoken {
        version: a2a::VERSION,
        base: "/a2a",
        bindings: &[TRANSPORT_PROTOCOL_HTTP_JSON, TRANSPORT_PROTOCOL_JSONRPC],
    },
    Spoken {
        version: "0.3",
        base: "/a2a/0.3",
        bindings: &[TRANSPORT_PROTOCOL_HTTP_JSON, TRANSPORT_PROTOCOL_JSONRPC],
    },
];

/// A send laye answers: the version and binding it arrived in, and what its
/// answer carries.
#[derive(Debug, PartialEq)]
pub struct Send {
    pub version: String,
    pub binding: String,
    /// The JSON-RPC request's id, answered under the same.
    rpc: Option<JsonRpcId>,
    context: String,
}

/// What `path` is beneath `at`: empty when it is `at`. None when it is not
/// beneath it.
fn beneath<'a>(path: &'a str, at: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(at)?;
    (rest.is_empty() || rest.starts_with('/')).then_some(rest)
}

/// The send a POST to `path` is: in the version whose base is the deepest
/// that holds it, over the binding that takes it. None is no send laye takes.
pub fn send_of(path: &str, body: &[u8]) -> Option<Send> {
    let path = path.split_once('?').map_or(path, |(p, _)| p);
    let body: Value = serde_json::from_slice(body).ok()?;
    let spoken = SPOKEN
        .iter()
        .filter(|s| beneath(path, s.base).is_some())
        .max_by_key(|s| s.base.len())?;
    let under = beneath(path, spoken.base)?;
    spoken.bindings.iter().find_map(|binding| {
        let context = taken(spoken.version, binding, under, &body)?;
        let rpc = if *binding == TRANSPORT_PROTOCOL_JSONRPC {
            serde_json::from_value::<JsonRpcId>(body.get("id").cloned().unwrap_or(Value::Null)).ok()
        } else {
            None
        };
        Some(Send {
            version: spoken.version.to_string(),
            binding: binding.to_string(),
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
