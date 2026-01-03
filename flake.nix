{
  description = "Vaultic - A secure, local-first password manager";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
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
          extensions = [ "rust-src" "rust-analyzer" ];
        };

        # Native build inputs needed for compilation
        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
          clang
          llvm
        ];

        # Libraries needed at build and runtime
        buildInputs = with pkgs; [
          # For GPG/sequoia-openpgp
          nettle
          gmp
          openssl

          # For FIDO2/hidapi
          udev

          # For X11 clipboard support
          xorg.libX11
          xorg.libXmu

          # General
          sqlite
        ];

      in {
        devShells.default = pkgs.mkShell {
          inherit nativeBuildInputs buildInputs;

          shellHook = ''
            echo "Vaultic development environment"
            echo "Rust: $(rustc --version)"
            echo ""
            echo "Build commands:"
            echo "  cargo build          - Debug build"
            echo "  cargo build --release - Release build"
            echo "  cargo test           - Run tests"
            echo "  cargo run -- --help  - Show help"
          '';

          # Required for bindgen/clang
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          # For pkg-config to find libraries
          PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" buildInputs;

          # Ensure linker can find libraries
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath buildInputs;
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "vaultic";
          version = "0.1.0";
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          inherit nativeBuildInputs buildInputs;

          # Enable all features for full build
          buildFeatures = [ "fido2" "gpg" ];

          meta = with pkgs.lib; {
            description = "A secure, local-first password manager with FIDO2 and AI support";
            homepage = "https://github.com/punitmishra/vaultic";
            license = licenses.mit;
            maintainers = [];
          };
        };
      }
    );
}
