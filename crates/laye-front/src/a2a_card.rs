//! laye's own card: the versions it speaks, where, and signed by laye's key as
//! a2a-go signs and verifies a card (a2acrypto: JWS over the card in JCS,
//! RFC 8785, without its signatures).

// "and laye is like the place"
// "for agents"
// "talkign to agents"
// "laye is foundational, while QNTX can remain to be doing experimental things"
//
// The card is read in 1.0 and in 0.3: 1.0's shape is a2a-rs's, and 0.3's keys
// sit beside it in the same object, as QNTX's card has them.

use std::collections::HashMap;

use a2a::{
    AgentCapabilities, AgentCard, AgentInterface, AgentSkill, HttpAuthSecurityScheme,
    SecurityScheme,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use laye_me::Keypair;
use serde_json::{Map, Value, json};

use crate::a2a_spoken::SPOKEN;

/// The scheme a session signs its requests in, as laye reads them.
const SIGNED: &str = "signed";

/// laye's card, as served from `origin`: signed by `key`, which `did` names.
pub fn card(origin: &str, did: &str, key: &Keypair) -> Result<Vec<u8>, String> {
    let interfaces: Vec<AgentInterface> = SPOKEN
        .iter()
        .flat_map(|spoken| {
            spoken.bindings.iter().map(|binding| AgentInterface {
                url: format!("{origin}{}", spoken.base),
                protocol_binding: binding.to_string(),
                protocol_version: spoken.version.to_string(),
                tenant: None,
            })
        })
        .collect();
    let described =
        "Signed by a session's own key, for this origin, short-lived and presented once.";
    let card = AgentCard {
        name: "laye".into(),
        description: "the place for agents talking to agents".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        supported_interfaces: interfaces,
        capabilities: AgentCapabilities::default(),
        default_input_modes: vec!["text/plain".into()],
        default_output_modes: vec!["text/plain".into()],
        skills: vec![AgentSkill {
            id: "say".into(),
            name: "say".into(),
            description: "Say something to an agent.".into(),
            tags: vec!["agents".into()],
            examples: None,
            input_modes: None,
            output_modes: None,
            security_requirements: None,
        }],
        provider: None,
        documentation_url: None,
        icon_url: None,
        security_schemes: Some(HashMap::from([(
            SIGNED.to_string(),
            SecurityScheme::HttpAuth(HttpAuthSecurityScheme {
                scheme: "Signed".into(),
                description: Some(described.into()),
                bearer_format: Some("JWT".into()),
            }),
        )])),
        security_requirements: Some(vec![HashMap::from([(SIGNED.to_string(), Vec::new())])]),
        signatures: None,
    };
    let mut card = serde_json::to_value(&card).map_err(|e| e.to_string())?;
    in_03(&mut card, origin, described);
    sign(&mut card, did, key)?;
    serde_json::to_vec(&card).map_err(|e| e.to_string())
}

/// 0.3's keys, beside 1.0's: the 0.3 row's first binding is where a 0.3
/// client goes, the rest its other interfaces.
fn in_03(card: &mut Value, origin: &str, described: &str) {
    let Some(at_03) = SPOKEN.iter().find(|s| s.version == "0.3") else {
        return;
    };
    let url = format!("{origin}{}", at_03.base);
    let Some(object) = card.as_object_mut() else {
        return;
    };
    object.insert("protocolVersion".into(), json!(at_03.version));
    object.insert("url".into(), json!(url));
    if let Some((first, rest)) = at_03.bindings.split_first() {
        object.insert("preferredTransport".into(), json!(first));
        let others: Vec<Value> = rest
            .iter()
            .map(|binding| json!({ "transport": binding, "url": url }))
            .collect();
        object.insert("additionalInterfaces".into(), json!(others));
    }
    object.insert("security".into(), json!([{ SIGNED: [] }]));
    if let Some(scheme) = object
        .get_mut("securitySchemes")
        .and_then(|schemes| schemes.get_mut(SIGNED))
        .and_then(Value::as_object_mut)
    {
        scheme.insert("type".into(), json!("http"));
        scheme.insert("scheme".into(), json!("Signed"));
        scheme.insert("bearerFormat".into(), json!("JWT"));
        scheme.insert("description".into(), json!(described));
    }
}

/// `card` signed by `key` under `did`'s key id, as a2a-go's a2acrypto signs:
/// a JWS whose payload is the card in JCS, without its signatures.
fn sign(card: &mut Value, did: &str, key: &Keypair) -> Result<(), String> {
    let kid = format!("{did}#{}", did.strip_prefix("did:key:").unwrap_or(did));
    let protected = B64URL.encode(
        serde_json::to_vec(&json!({ "alg": "EdDSA", "kid": kid, "typ": "JOSE" }))
            .map_err(|e| e.to_string())?,
    );
    if let Some(object) = card.as_object_mut() {
        object.remove("signatures");
    }
    let payload = B64URL.encode(jcs(card)?);
    let signature = key
        .sign(format!("{protected}.{payload}").as_bytes())
        .map_err(|e| e.to_string())?;
    if let Some(object) = card.as_object_mut() {
        object.insert(
            "signatures".into(),
            json!([{ "protected": protected, "signature": B64URL.encode(signature) }]),
        );
    }
    Ok(())
}

/// `value` in JCS (RFC 8785): members ordered by their names' UTF-16 code
/// units, no whitespace, strings escaped as JSON must and no more.
pub fn jcs(value: &Value) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    write_jcs(&mut out, value)?;
    Ok(out.into_bytes())
}

fn write_jcs(out: &mut String, value: &Value) -> Result<(), String> {
    match value {
        Value::Object(members) => write_object(out, members),
        Value::Array(items) => {
            out.push('[');
            for (at, item) in items.iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                write_jcs(out, item)?;
            }
            out.push(']');
            Ok(())
        }
        // An integer is written as JCS writes it; laye's card carries no other
        // number.
        Value::Number(n) if n.is_i64() || n.is_u64() => {
            out.push_str(&n.to_string());
            Ok(())
        }
        Value::Number(n) => Err(format!(
            "{n} is no integer, and laye writes no other in JCS"
        )),
        // serde_json escapes a string as JCS does: ", \\, and the control
        // characters, as \b \f \n \r \t or \u00xx.
        other => {
            out.push_str(&serde_json::to_string(other).map_err(|e| e.to_string())?);
            Ok(())
        }
    }
}

fn write_object(out: &mut String, members: &Map<String, Value>) -> Result<(), String> {
    let mut names: Vec<&String> = members.keys().collect();
    names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    out.push('{');
    for (at, name) in names.into_iter().enumerate() {
        if at > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(name).map_err(|e| e.to_string())?);
        out.push(':');
        if let Some(value) = members.get(name) {
            write_jcs(out, value)?;
        }
    }
    out.push('}');
    Ok(())
}
