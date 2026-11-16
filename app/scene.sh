#!/usr/bin/env bash
# The scene the page is drawn on, built into the page: crates/laye-scene to
# wasm, and wasm-bindgen's loader beside it at web/scene/.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' \
  cargo build --manifest-path "$root/Cargo.toml" --profile scene --target wasm32-unknown-unknown -p laye-scene
# The wasm-bindgen CLI has to be the version crates/laye-scene pins: the one on
# PATH when it is that one (CI installs it), else nix's.
pinned=0.2.121
bindgen=(wasm-bindgen)
if [ "$(wasm-bindgen --version 2>/dev/null)" != "wasm-bindgen $pinned" ]; then
  bindgen=(nix shell "github:NixOS/nixpkgs/nixos-unstable#wasm-bindgen-cli_${pinned//./_}" --command wasm-bindgen)
fi
"${bindgen[@]}" "$root/target/wasm32-unknown-unknown/scene/laye_scene.wasm" \
  --target web --out-dir "$here/web/scene" --no-typescript
