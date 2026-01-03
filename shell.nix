# Legacy shell.nix for users without flakes
# Prefer using `nix develop` with flake.nix instead

{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    # Rust toolchain
    rustc
    cargo
    clippy
    rustfmt
    rust-analyzer

    # Build tools
    pkg-config
    clang
    llvmPackages.libclang
  ];

  buildInputs = with pkgs; [
    # For GPG/sequoia-openpgp (optional feature)
    nettle
    gmp
    openssl

    # For FIDO2/hidapi (optional feature)
    udev
    hidapi

    # For clipboard support
    libxkbcommon
  ] ++ lib.optionals stdenv.isLinux [
    xorg.libX11
    xorg.libXcursor
    xorg.libXrandr
    xorg.libXi
    wayland
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.AppKit
    darwin.apple_sdk.frameworks.Security
  ];

  shellHook = ''
    echo "🔐 Vaultic Development Environment (shell.nix)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Tip: Consider using 'nix develop' with flakes for better reproducibility"
    echo ""
    echo "Build commands:"
    echo "  cargo build                    - Debug build"
    echo "  cargo build --release          - Release build"
    echo "  cargo build --all-features     - Build with FIDO2 + GPG"
    echo "  cargo test                     - Run tests"
  '';

  # Required for bindgen/clang
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

  # Rust backtrace
  RUST_BACKTRACE = "1";
}
