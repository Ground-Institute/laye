# The app workflow, emitted to .github/workflows/app.yml and never edited by hand:
#   nix eval --json --file ci/app.nix | jq . > .github/workflows/app.yml
#
# "make it so i get to see a screenshot of the screen"
# "make sure it has serious ci. ilike QNTX app does"
let
  # The ios-common tag is the one app/Cargo.toml takes the sheet from, so the
  # sheet and the job that ships it are one version.
  tag = (builtins.fromTOML (builtins.readFile ../app/Cargo.toml)).dependencies.sheet.tag;
  ios = import "${builtins.fetchGit {
    url = "https://github.com/teranos/ios-common";
    ref = "refs/tags/${tag}";
  }}/ci/ios.nix";
  wasmBindgen = "0.2.121";
  bindgen = arch: {
    name = "wasm-bindgen ${wasmBindgen}";
    run = ''
      curl -sSL "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${wasmBindgen}/wasm-bindgen-${wasmBindgen}-${arch}.tar.gz" | tar -xz
      echo "$PWD/wasm-bindgen-${wasmBindgen}-${arch}" >> "$GITHUB_PATH"
    '';
  };
  rust = targets: components: {
    id = "rust";
    uses = "dtolnay/rust-toolchain@stable";
    "with" = { inherit targets; } // (if components == null then { } else { inherit components; });
  };
  cache = name: {
    uses = "actions/cache@v4";
    "with" = {
      path = "target";
      key = "${name}-\${{ steps.rust.outputs.cachekey }}-\${{ hashFiles('Cargo.lock') }}";
      restore-keys = "${name}-\${{ steps.rust.outputs.cachekey }}-";
    };
  };
in
{
  name = "app";
  on = {
    push = { };
    pull_request = { };
    workflow_dispatch = { };
  };
  jobs = {
    # The workspace answers for itself, the scene builds for the browser, and
    # every workflow is what its nix says.
    checks = {
      runs-on = "ubuntu-latest";
      steps = [
        { uses = "actions/checkout@v5"; }
        (rust "wasm32-unknown-unknown" "clippy")
        (cache "workspace")
        # laye-grant builds its proto with prost, which runs protoc.
        {
          name = "protoc";
          run = "sudo apt-get install -y --no-install-recommends protobuf-compiler";
        }
        # Names are kept in etcd, and their tests run a real one: the version
        # q, k and l run.
        {
          name = "etcd 3.7.3";
          run = ''
            curl -fsSLO https://github.com/etcd-io/etcd/releases/download/v3.7.3/etcd-v3.7.3-linux-amd64.tar.gz
            echo "5dfa9cc3b3ce3b4b491fbcc2057d3daa166bcc6676f743fcd20f8e5760cb9775  etcd-v3.7.3-linux-amd64.tar.gz" | sha256sum --check
            tar -xzf etcd-v3.7.3-linux-amd64.tar.gz
            echo "$PWD/etcd-v3.7.3-linux-amd64" >> "$GITHUB_PATH"
          '';
        }
        {
          name = "Every crate's tests";
          run = "cargo test --workspace --exclude laye-scene";
        }
        {
          name = "The scene answers for every warning";
          env.RUSTFLAGS = ''--cfg getrandom_backend="wasm_js"'';
          run = "cargo clippy --target wasm32-unknown-unknown -p laye-scene -- -D warnings";
        }
        { uses = "cachix/install-nix-action@v31"; }
        {
          name = "Every workflow is what its nix says";
          run = ''
            for f in ci/*.nix; do
              nix eval --json --file "$f" | jq . | diff - ".github/workflows/$(basename "$f" .nix).yml"
            done
          '';
        }
      ];
    };

    # The page as a phone shows it, photographed: the stranger screen, the light
    # becoming the symbol, and the symbol locked.
    screens = {
      runs-on = "ubuntu-latest";
      steps = [
        { uses = "actions/checkout@v5"; }
        (rust "wasm32-unknown-unknown" null)
        (cache "scene")
        (bindgen "x86_64-unknown-linux-musl")
        {
          name = "The scene, into the page";
          run = "app/scene.sh";
        }
        {
          name = "Photograph the screen";
          run = ''
            python3 -m http.server 8932 --directory app >/dev/null 2>&1 &
            google-chrome --headless=new --no-sandbox --enable-unsafe-swiftshader --use-angle=swiftshader \
              --remote-debugging-port=9333 --user-data-dir="$RUNNER_TEMP/chrome" about:blank >/dev/null 2>&1 &
            until curl -s 127.0.0.1:9333/json/version >/dev/null; do sleep 0.5; done
            mkdir -p screens
            node app/ci/screens.mjs 9333 http://127.0.0.1:8932/web/index.html 8000:screens/laye.png
            node app/ci/screens.mjs 9333 http://127.0.0.1:8932/ci/known.html 4000:screens/becoming.png 30000:screens/known.png
          '';
        }
        {
          uses = "actions/upload-artifact@v4";
          "with" = {
            name = "screens";
            path = "screens/*.png";
          };
        }
      ];
    };

    # The app for a phone: teranos/ios-common's job, with laye's page made by
    # its scene.
    ios = ios {
      dir = "app";
      inherit tag;
      profile = (builtins.fromJSON (builtins.readFile ../app/apple.json)).profile;
      targets = [ "wasm32-unknown-unknown" ];
      cache = {
        path = [
          "target"
          "app/target"
        ];
        key = [
          "Cargo.lock"
          "app/Cargo.lock"
        ];
      };
      prepare = [
        (bindgen "aarch64-apple-darwin")
        {
          name = "The scene, into the page";
          run = "./scene.sh";
        }
      ];
    };
  };
}
