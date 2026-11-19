# laye, the app

> think of laye like an authentication app

> auth and identity

> laye is calm

The key you are is made in the app and never leaves it. An account proves
itself once, in the provider ceremony, and the binding the ceremony signs is
held beside the key. A node's login page at `laye.ground.institute` hands its
journey to the app as `laye://sign?<journey>`. The app answers laye's
challenge with the key and the binding, and opens the page laye sends you
back to.

The scene behind the page is `crates/laye-scene`, from teranos/laye's
bevy-starter: the bowl, the one light, the camera above and behind it. The
light warms once laye knows you.

## Build

```
cargo tauri dev          # desktop
cargo tauri ios init     # writes gen/apple
cargo tauri ios build
```

`scene.sh` builds the scene to wasm into `web/scene/` before each of them,
with the wasm-bindgen CLI at the version `crates/laye-scene` pins, from nix.

## What the node has to name

The ceremony sends the app back to `laye://door`. A node returns a ceremony
only to an origin one of its doors names in `am.toml`, so q's
`[auth.door.laye]` has to name it:

```toml
[auth.door.laye]
origins = ["https://laye.ground.institute", "laye://door"]
```

## Taken from teranos/ios-common

The tag `app/Cargo.toml` names for `sheet` is the ios-common `ci/app.nix`
imports: its `ios` job is ios-common's `ci/ios.nix`, with laye's scene as the
page. Every workflow is emitted from `ci/*.nix` and never edited by hand.

- `sheet`: `ASWebAuthenticationSession`, one command, `run`.
- `apple/apple.py`: laye's App IDs and capabilities (`apple.json`), and the profile.
- `apple/ios-project.py`: signing against the profile instead of an account.
- `apple/upload.sh` and `apple/delivered.py`: to TestFlight, and green once testers can install.

The island comes to ios-common next (`PLAN.md`, `P2P2A2A_A_003_05`).

From QNTX-App, as it is there:

- `Info.ios.plist` answers export compliance in the bundle.
- The Tauri, opener and deep-link versions are the ones QNTX-App pins.

## Apple

What Apple holds for laye, team `88645J88Q8`:

| What | Identifier |
|---|---|
| App ID, named Ground Institute laye | `laye.ground.institute` |
| Services ID, named Ground Institute laye service: Sign in with Apple on the web, returning to `https://laye.ground.institute/auth/binding/callback` | `services.laye.ground.institute` |
| Sign in with Apple key, primary App ID `laye.ground.institute` | `B25XSNYP25`; the `.p8` is SSM SecureString `/laye/apple/private-key` in q's account |

The App IDs' capabilities are `apple.json`, and `P2P2A2A_A_003_01` in PLAN.md.

Still done by a person:

- The app in App Store Connect: the API lists, reads and modifies apps, and creates none. Its Apple ID goes into this repo's variable `APPLE_APP_ID`.
- The team's signing secrets in this repo, under the names QNTX-App holds them:
  - `APPLE_DEVELOPMENT_TEAM`
  - `IOS_CERTIFICATE`, `IOS_CERTIFICATE_PASSWORD`
  - `APPLE_API_KEY`, `APPLE_API_ISSUER`, `APPLE_API_KEY_CONTENT`

The provisioning profile is made by CI (ios-common's `apple/apple.py`) against the certificate in `IOS_CERTIFICATE`.
