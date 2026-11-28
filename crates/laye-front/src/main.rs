//! laye-front <laye.toml>: laye in front of QNTX. Its settings are its own
//! file, apart from QNTX's am.toml; `laye.toml` in this crate is one.
//! Says who it is and where it listens, one JSON line on stdout. A failure is
//! one sacred-error JSON line on stderr.

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Deserialize)]
struct File {
    listen: String,
    key: PathBuf,
    held: PathBuf,
    invitations: PathBuf,
    ceremony: String,
    public_origins: Vec<String>,
    root_identities: Vec<String>,
    binding_signers: Vec<String>,
    issuer: String,
    #[serde(default)]
    nodes: Vec<laye_front::Node>,
    qntx: Qntx,
    #[serde(default)]
    names: Option<laye_front::NamesAt>,
    #[serde(default)]
    passkeys: Option<laye_front::passkeys::PasskeysAt>,
    #[serde(default)]
    web: Option<std::path::PathBuf>,
    #[serde(default)]
    apns: Option<laye_front::apns::ApnsAt>,
    #[serde(default)]
    pack_nodes: Vec<String>,
    /// The file `ground laye json` wrote: what ground's pbt says of this laye.
    #[serde(default)]
    governed_by: Option<PathBuf>,
}

/// What ground's pbt says of this laye, read whole from the file ground wrote;
/// none when the settings name no such file.
fn governed(
    at: Option<&PathBuf>,
) -> Result<Option<laye_front::Governed>, Box<sacred_error::Error>> {
    let Some(at) = at else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(at).map_err(|e| {
        laye_peer::error(
            "governed_by",
            "what ground says of laye does not read",
            format!("{}: {e}", at.display()),
        )
    })?;
    serde_json::from_str(&text).map(Some).map_err(|e| {
        laye_peer::error(
            "governed_by",
            "what ground says of laye is not what `ground laye json` writes",
            format!("{}: {e}", at.display()),
        )
    })
}

#[derive(Deserialize)]
struct Qntx {
    origin: String,
    did: String,
}

fn fail(error: &sacred_error::Error) -> ! {
    match serde_json::to_string(error) {
        Ok(line) => eprintln!("{line}"),
        Err(e) => eprintln!("{error:?}; and it did not serialize: {e}"),
    }
    std::process::exit(1)
}

fn settings() -> Result<File, Box<sacred_error::Error>> {
    let path = std::env::args().nth(1).ok_or_else(|| {
        laye_peer::error(
            "args",
            "laye-front was not told where its settings are",
            "laye-front <laye.toml>",
        )
    })?;
    let text = std::fs::read_to_string(&path).map_err(|e| {
        laye_peer::error(
            "settings",
            "laye's settings do not read",
            format!("{path}: {e}"),
        )
    })?;
    toml::from_str(&text).map_err(|e| {
        laye_peer::error(
            "settings",
            "laye's settings are not what laye takes",
            format!("{path}: {e}"),
        )
    })
}

#[tokio::main]
async fn main() {
    let file = settings().unwrap_or_else(|e| fail(&e));
    let listen = file.listen.parse().unwrap_or_else(|e| {
        fail(&laye_peer::error(
            "settings",
            "listen is not an address",
            format!("{}: {e}", file.listen),
        ))
    });
    let key = laye_peer::key_at(&file.key).unwrap_or_else(|e| fail(&e));
    let governed = governed(file.governed_by.as_ref()).unwrap_or_else(|e| fail(&e));
    let (front, run) = laye_front::start(
        laye_front::Config {
            listen,
            qntx: file.qntx.origin.trim_end_matches('/').to_string(),
            qntx_did: file.qntx.did,
            public_origins: file
                .public_origins
                .iter()
                .map(|origin| origin.trim_end_matches('/').to_string())
                .collect(),
            held_at: file.held,
            root_identities: file.root_identities,
            binding_signers: file.binding_signers,
            issuer: file.issuer.trim_end_matches('/').to_string(),
            nodes: file.nodes,
            invitations_at: file.invitations,
            ceremony_at: file.ceremony.trim_end_matches('/').to_string(),
            names: file.names,
            passkeys: file.passkeys,
            web: file.web,
            apns: file.apns,
            pack_nodes: file.pack_nodes,
            governed,
        },
        key,
    )
    .await
    .unwrap_or_else(|e| fail(&e));
    println!(
        "{}",
        serde_json::json!({ "did": front.did, "listening": front.addr.to_string() })
    );
    if let Err(e) = run.await {
        fail(&laye_peer::error("run", "laye stopped", e.to_string()));
    }
}
