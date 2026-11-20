//! An invitation laye holds, mailed by QNTX in laye's own look.

// "1. but laye could use QNTX to send mail."
// "right, and QNTX mail allows you to set a custom template, try to make it fit laye theme"
// "A mail actually goes out to both me and my friend"
// "the MAIL ROOT received has a button for cancelling the invitation"

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;

use crate::invitations::Invitation;
use crate::{Inner, jwt};

/// Where QNTX mails an invitation laye holds.
const INVITED: &str = "/auth/laye/invited";

/// laye's mail: its look, filled by QNTX as a plugin's template is.
fn template() -> serde_json::Value {
    serde_json::json!({
        "subject": "{{.subject}}",
        "text": "{{.body}}\n\n{{.link_label}}:\n{{.link}}\n\nlaye.ground.institute\n",
        "html": include_str!("mail.html"),
    })
}

/// The accounts an invitation lets in, as a person reads them.
fn signs_in_with(inv: &Invitation) -> String {
    inv.accounts
        .iter()
        .map(|a| format!("{} {}", a.provider, a.account))
        .collect::<Vec<_>>()
        .join(" or ")
}

/// What laye asks QNTX to send for an invitation: the friend's mail and the
/// root's copy with its cancel. None when the invitation names no address.
pub(crate) fn invited(inv: &Invitation, laye: &str) -> Option<serde_json::Value> {
    let email = inv.email.as_deref()?;
    let accounts = signs_in_with(inv);
    Some(serde_json::json!({
        "invitation": inv.id,
        "email": email,
        "invited_by": inv.invited_by,
        "friend": {
            "template": template(),
            "values": {
                "subject": "You are invited to laye",
                "body": format!("{} invites you to laye.\n\nSign in with {accounts}.", inv.invited_by),
                "link": format!("{laye}/laye/me"),
                "link_label": "Accept the invitation",
            },
        },
        "root": {
            "template": template(),
            "values": {
                "subject": format!("You invited {email}"),
                "body": format!("You invited {email} to laye, to sign in with {accounts}."),
                "link": format!("{laye}/laye/me?cancel={}", inv.id),
                "link_label": "Cancel the invitation",
            },
        },
    }))
}

/// QNTX mails the invitation, asked by laye signing as itself. Err is why it
/// did not.
pub(crate) async fn send(inner: &Inner, asked: serde_json::Value) -> Result<(), String> {
    let now = crate::now();
    let signed = jwt::sign(
        &inner.key,
        &jwt::Claims {
            iss: inner.did.clone(),
            sub: inner.did.clone(),
            aud: vec![inner.config.qntx_did.clone()],
            exp: now + 60,
            iat: now,
            jti: jwt::fresh_jti(),
            label: "laye".into(),
        },
    )
    .map_err(|e| e.to_string())?;
    let req = Request::post(format!("{}{INVITED}", inner.config.qntx))
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
    let said = resp
        .into_body()
        .collect()
        .await
        .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
        .unwrap_or_default();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("QNTX answered {status}: {said}"))
    }
}
