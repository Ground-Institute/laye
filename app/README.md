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

## Taken from QNTX-App

- `sheet/` is QNTX-App's `sheet/`: `ASWebAuthenticationSession`, one command, `run`.
- `Info.ios.plist` answers export compliance in the bundle, as QNTX-App's does.
- The Tauri, opener and deep-link versions are the ones QNTX-App pins.

Both apps could use the following from one place:

- `sheet/`, which is the same code in both apps.
- The TestFlight pipeline: `ci/testflight.nix`, `.github/scripts/ios-project.py`
  (signing against a profile instead of an account) and
  `.github/scripts/delivered.py` (a build counts as delivered once App Store
  Connect says testers can install it).

## Apple

These steps are done by a person:

- App ID `institute.ground.laye`.
- An App Store provisioning profile for it, and the distribution certificate.
- The app in App Store Connect.
- The secrets the TestFlight pipeline reads, under the names QNTX-App uses:
  - `APPLE_DEVELOPMENT_TEAM`
  - `IOS_CERTIFICATE`, `IOS_CERTIFICATE_PASSWORD`
  - `IOS_MOBILE_PROVISION`, `PROVISIONING_PROFILE`
  - `APPLE_API_KEY`, `APPLE_API_ISSUER`, `APPLE_API_KEY_CONTENT`
  - `APPLE_APP_ID`
