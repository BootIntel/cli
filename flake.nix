# Nix flake for bootintel-cli.
#
# Reproducible builds without pulling anything from crates.io during
# `nix build` (Cargo.lock is the lockfile; nix vendors from it).
#
# Usage:
#   nix build .#bootintel        # produces ./result/bin/bootintel
#   nix run .# -- version        # runs bootintel version
#   nix develop                  # drops into a shell with rust + cargo
#
# In-repo only — not published to any Nix registry. Add
# `inputs.bootintel-cli.url = "github:bootintel/cli";`
# to consume from another flake.

{
  description = "bootintel-cli — interactive UART capture + streaming boot-log analysis";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Feature set. `tui` is optional; toggle via `nix build .#bootintel-tui`
        # once we want a separate derivation. Default is the full-featured
        # binary that matches what install.sh delivers.
        features = [ "tui" ];

        bootintel = pkgs.rustPlatform.buildRustPackage {
          pname = "bootintel-cli";
          version = "0.3.1";

          # Build from this directory (the repo root).
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          buildFeatures = features;

          # serialport needs libudev on Linux; arboard needs X/Wayland
          # backends (only reached when the clipboard feature runs).
          buildInputs = with pkgs; lib.optionals stdenv.isLinux [
            udev
            xorg.libxcb
          ];

          nativeBuildInputs = with pkgs; [ pkg-config ];

          # Skip `cargo test` inside nix — the integration tests spawn a
          # TCP listener, which some Nix sandbox modes disallow. `cargo
          # test` is run in CI + locally instead.
          doCheck = false;

          meta = with pkgs.lib; {
            description = "Interactive UART capture + streaming boot-log analysis";
            homepage = "https://bootintel.com";
            license = licenses.asl20;
            maintainers = [ ];
            mainProgram = "bootintel";
          };
        };
      in
      {
        packages = {
          default = bootintel;
          bootintel = bootintel;
        };

        apps.default = {
          type = "app";
          program = "${bootintel}/bin/bootintel";
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc
            cargo
            rust-analyzer
            pkg-config
            udev
          ];
        };
      });
}
