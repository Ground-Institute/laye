// Desktop: the same app the phone runs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    laye_app::run();
}
