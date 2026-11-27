//! The A2UI an agent says beside its words, as laye keeps it.

// "Getting A2UI pieces to show up in another session from this one"
// "i expect my own workflow to not change"
//
// A2UI over A2A, the v1.0 extension specification at the commit laye pins
// (parity/a2ui_v1.0_36725ee/SOURCE): a DataPart whose metadata mimeType is
// application/a2ui+json carries A2UI messages, and of its data:
// "It MUST be an array of messages."
// a2a-lf's Part has A2A's own mediaType beside metadata, which the A2UI SDK
// sets to the same (python/a2ui_a2a/src/a2ui/a2a/_compat.py make_data_part).

use a2a::{Part, PartContent};
use serde_json::Value;

/// The MIME type of a part that carries A2UI v1.0 messages.
pub const MIME: &str = "application/a2ui+json";

/// Whether a part says it carries A2UI.
fn is_a2ui(part: &Part) -> bool {
    part.media_type.as_deref() == Some(MIME)
        || part
            .metadata
            .as_ref()
            .and_then(|m| m.get("mimeType"))
            .and_then(Value::as_str)
            == Some(MIME)
}

/// Every A2UI message among `parts`, in the order said; or why what a part
/// says is A2UI is no list of A2UI messages, by the part's place among them.
pub fn messages_of(parts: &[Part]) -> Result<Vec<Value>, String> {
    let mut messages = Vec::new();
    for (at, part) in parts.iter().enumerate() {
        if !is_a2ui(part) {
            continue;
        }
        let PartContent::Data(Value::Array(said)) = &part.content else {
            return Err(format!(
                "A2UI data is a list of A2UI messages, and part {at}'s is not"
            ));
        };
        if let Some(i) = said.iter().position(|m| !m.is_object()) {
            return Err(format!(
                "A2UI data is a list of A2UI messages, and part {at}'s message {i} is no object"
            ));
        }
        messages.extend(said.iter().cloned());
    }
    Ok(messages)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parts(v: Value) -> Vec<Part> {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn what_says_no_a2ui_has_none() {
        assert_eq!(
            messages_of(&parts(
                json!([{ "text": "the tide is in" }, { "data": [1] }])
            ))
            .unwrap(),
            Vec::<Value>::new()
        );
    }

    #[test]
    fn a2ui_is_its_messages_in_the_order_said_by_either_name_of_its_type() {
        let one = json!({ "version": "1.0", "deleteSurface": { "surfaceId": "a" } });
        let two = json!({ "version": "1.0", "deleteSurface": { "surfaceId": "b" } });
        let said = parts(json!([
            { "text": "x" },
            { "data": [one], "metadata": { "mimeType": MIME } },
            { "data": [two], "mediaType": MIME },
        ]));
        assert_eq!(messages_of(&said).unwrap(), vec![one, two]);
    }

    #[test]
    fn a2ui_that_is_no_list_of_messages_says_which_part() {
        let said =
            parts(json!([{ "text": "x" }, { "data": { "version": "1.0" }, "mediaType": MIME }]));
        assert_eq!(
            messages_of(&said).unwrap_err(),
            "A2UI data is a list of A2UI messages, and part 1's is not"
        );
        let said = parts(json!([{ "data": [{ "version": "1.0" }, "x"], "mediaType": MIME }]));
        assert_eq!(
            messages_of(&said).unwrap_err(),
            "A2UI data is a list of A2UI messages, and part 0's message 1 is no object"
        );
    }
}
