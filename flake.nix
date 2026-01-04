{
  description = "Vaultic - A secure, local-first password manager";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };

        # Common build inputs for both dev shell and package
        commonBuildInputs = with pkgs; [
          # For GPG/sequoia-openpgp (optional feature)
          nettle
          gmp
          openssl

          # For FIDO2/hidapi (optional feature)
          udev
          hidapi

          # For clipboard support (arboard)
          libxkbcommon
        ] ++ lib.optionals stdenv.isLinux [
          # Linux-specific clipboard deps
          xorg.libX11
          xorg.libXcursor
          xorg.libXrandr
          xorg.libXi
          wayland
        ] ++ lib.optionals stdenv.isDarwin [
          darwin.apple_sdk.frameworks.AppKit
          darwin.apple_sdk.frameworks.Security
        ];

        commonNativeBuildInputs = with pkgs; [
          pkg-config
          clang
          llvmPackages.libclang
        ];

      in {
        # Development shell with all tools
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = commonNativeBuildInputs ++ [ rustToolchain ];
          buildInputs = commonBuildInputs;

          shellHook = ''
            echo "🔐 Vaultic Development Environment"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "Rust: $(rustc --version)"
            echo "Cargo: $(cargo --version)"
            echo ""
            echo "Build commands:"
            echo "  cargo build                    - Debug build (no FIDO2/GPG)"
            echo "  cargo build --release          - Release build"
            echo "  cargo build --all-features     - Build with FIDO2 + GPG"
            echo "  cargo test                     - Run tests"
            echo "  cargo run -- --help            - Show CLI help"
            echo ""
            echo "Features available:"
            echo "  --features fido2   - YubiKey/FIDO2 support"
            echo "  --features gpg     - GPG/OpenPGP support"
            echo "  --all-features     - Everything"
          '';

          # Required for bindgen/clang
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          # Rust backtrace for debugging
          RUST_BACKTRACE = "1";
        };

        # Minimal dev shell (no optional features' deps)
        devShells.minimal = pkgs.mkShell {
          nativeBuildInputs = [ rustToolchain pkgs.pkg-config ];
          buildInputs = with pkgs; [
            openssl
          ] ++ lib.optionals stdenv.isLinux [
            xorg.libX11
            libxkbcommon
          ];

          shellHook = ''
            echo "🔐 Vaultic Minimal Dev Environment"
            echo "Note: FIDO2 and GPG features not available"
          '';
        };

        # Package build
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "vaultic";
          version = "0.1.0";
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = commonNativeBuildInputs;
          buildInputs = commonBuildInputs;

          # Build with all features
          buildFeatures = [ "fido2" "gpg" ];

          # Skip tests that need hardware
          checkFlags = [
            "--skip=fido2"
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          meta = with pkgs.lib; {
            description = "A secure, local-first password manager with FIDO2 and AI support";
            homepage = "https://github.com/punitmishra/vaultic";
            license = licenses.mit;
            platforms = platforms.linux ++ platforms.darwin;
            mainProgram = "vaultic";
          };
        };

        # Package without optional features (lighter deps)
        packages.minimal = pkgs.rustPlatform.buildRustPackage {
          pname = "vaultic";
          version = "0.1.0";
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = with pkgs; [ openssl ] ++
            lib.optionals stdenv.isLinux [ xorg.libX11 libxkbcommon ];

          # No optional features
          buildNoDefaultFeatures = false;

          meta = with pkgs.lib; {
            description = "Vaultic password manager (minimal build)";
            license = licenses.mit;
            mainProgram = "vaultic";
          };
        };
      }
    );
}
