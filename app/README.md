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

These move into a repo of their own that both apps use (`PLAN.md`, `P2P2A2A_A_003_09`):

- The island: QNTX-App's `island/` and its CI.
- `sheet/`, which is the same code in both apps.
- The generic steps of QNTX-App's TestFlight pipeline (`ci/testflight.nix`):
  - signing against a profile instead of an account (`.github/scripts/ios-project.py`);
  - registering App IDs and the profile (`ci/apple.py` here);
  - uploading with `xcrun altool --upload-package`, which names the app by `APPLE_APP_ID`;
  - waiting until App Store Connect says testers can install the build (`.github/scripts/delivered.py`).

  Its other steps are QNTX's own: checking out QNTX and QNTX-Web, taking the
  version from QNTX's newest tag, and the share extension.

## Apple

What Apple holds for laye, team `88645J88Q8`:

| What | Identifier |
|---|---|
| App ID, named Ground Institute laye | `laye.ground.institute` |
| Services ID, named Ground Institute laye service: Sign in with Apple on the web, returning to `https://laye.ground.institute/auth/binding/callback` | `services.laye.ground.institute` |
| Sign in with Apple key, primary App ID `laye.ground.institute` | `B25XSNYP25`; the `.p8` is SSM SecureString `/laye/apple/private-key` in q's account |

The App ID's capabilities are `P2P2A2A_A_003_01` in PLAN.md.

Still done by a person:

- The app in App Store Connect: the API lists, reads and modifies apps, and creates none. Its Apple ID goes into this repo's variable `APPLE_APP_ID`.
- The team's signing secrets in this repo, under the names QNTX-App holds them:
  - `APPLE_DEVELOPMENT_TEAM`
  - `IOS_CERTIFICATE`, `IOS_CERTIFICATE_PASSWORD`
  - `APPLE_API_KEY`, `APPLE_API_ISSUER`, `APPLE_API_KEY_CONTENT`

The provisioning profile is made by CI (`ci/apple.py`) against the certificate in `IOS_CERTIFICATE`.
