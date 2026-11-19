//! laye, on a phone.
//!
//! The page is everything laye says and does. This is what the page cannot do
//! from a WebView: the sheet a provider ceremony runs in, laye:// coming back
//! in, a node's page opened in the browser, and asking laye and the ceremony
//! without a browser in between.

// "think of laye like an authentication app"
// "auth and identity"

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let ran = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_http::init())
        .plugin(sheet::init())
        .run(tauri::generate_context!());
    if let Err(err) = ran {
        // The entry point answers to nobody: the reason goes to stderr, which
        // iOS keeps in the device log.
        eprintln!("laye did not run: {err}");
        std::process::exit(1);
    }
}
