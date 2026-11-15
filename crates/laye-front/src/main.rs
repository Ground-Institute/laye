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
    public_origin: String,
    qntx: Qntx,
}

#[derive(Deserialize)]
struct Qntx {
    origin: String,
    did: String,
}

fn fail(error: &sacred_error::Error) -> ! {
    match serde_json::to_string(error) {
        Ok(line) => eprintln!("{line}"),
        Err(e) => eprintln!(
            "{} ({}): {}; and it did not serialize: {e}",
            error.title, error.id, error.why
        ),
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
    let (front, run) = laye_front::start(
        laye_front::Config {
            listen,
            qntx: file.qntx.origin.trim_end_matches('/').to_string(),
            qntx_did: file.qntx.did,
            public_origin: file.public_origin.trim_end_matches('/').to_string(),
            held_at: file.held,
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
