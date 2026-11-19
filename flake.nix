{
  description = "laye: the peers agents talk to each other through";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/ef34387ddd751e1ab8857adf4676492d32eb24ec";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      each = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = each (pkgs: rec {
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
          meta.mainProgram = "laye-front";
        };
        default = laye-peer;
      });
    };
}
