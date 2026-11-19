{
  description = "laye: the peers agents talk to each other through";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/ef34387ddd751e1ab8857adf4676492d32eb24ec";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      each = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = each (pkgs: let
        # laye's glass, as vitreous makes it: "the projects take from the
        # design system, never the other way".
        vitreous = pkgs.fetchFromGitHub {
          owner = "teranos";
          repo = "vitreous";
          rev = "638f98d64844b38abb7ca68f1f8f5498c2b7bbf9";
          sha256 = "1ajc81fxx65dn4lj0wgm1kjh61rhmjmak2m51dcfah7lizpqb09p";
        };
      in rec {
        laye-peer = pkgs.rustPlatform.buildRustPackage {
          pname = "laye-peer";
          version = "0.0.0";
          src = self;
          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes."sacred-error-0.1.0" = "sha256-AFWB5DT1EjfHvjuODxri3Dw+vGYo/EAnTwF0xpJwSQQ=";
          };
          cargoBuildFlags = [ "-p" "laye-peer" ];
          cargoTestFlags = [ "-p" "laye-peer" ];
          meta.mainProgram = "laye-peer";
        };
        laye-front = pkgs.rustPlatform.buildRustPackage {
          pname = "laye-front";
          version = "0.0.0";
          src = self;
          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes."sacred-error-0.1.0" = "sha256-AFWB5DT1EjfHvjuODxri3Dw+vGYo/EAnTwF0xpJwSQQ=";
          };
          cargoBuildFlags = [ "-p" "laye-front" ];
          cargoTestFlags = [ "-p" "laye-front" ];
          # Names are kept in etcd, and their tests run a real one.
          nativeCheckInputs = [ pkgs.etcd ];
          # laye's page loads laye's wasm, from beside the binary.
          postInstall = ''
            mkdir -p $out/share/laye
            cp -r ${laye-web} $out/share/laye/web
          '';
          meta.mainProgram = "laye-front";
        };
        # laye in the browser: crates/laye-p2p as wasm, with the JS that loads
        # it, from the same commit as the laye-front that serves it.
        laye-web = pkgs.rustPlatform.buildRustPackage {
          pname = "laye-web";
          version = "0.0.0";
          src = self;
          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes."sacred-error-0.1.0" = "sha256-AFWB5DT1EjfHvjuODxri3Dw+vGYo/EAnTwF0xpJwSQQ=";
          };
          nativeBuildInputs = [ pkgs.wasm-bindgen-cli_0_2_121 pkgs.lld ];
          buildPhase = ''
            runHook preBuild
            CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER=lld \
              cargo build --offline --release --target wasm32-unknown-unknown -p laye-p2p
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            wasm-bindgen --target web --out-dir $out \
              target/wasm32-unknown-unknown/release/laye_p2p.wasm
            mkdir -p $out/vitreous
            cp ${vitreous}/*.css $out/vitreous/
            runHook postInstall
          '';
          doCheck = false;
        };
        default = laye-peer;
      });
    };
}
