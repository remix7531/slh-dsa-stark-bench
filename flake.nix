{
  description = "SPHINCS+ STARK batch verification PoC";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
          overlays = [ (import rust-overlay) ];
        };

        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };

        # risc0 Rust fork path (installed via `cargo risczero install`).
        # Has pre-compiled sysroot for riscv32im-risc0-zkvm-elf.
        risc0-toolchain = "$HOME/.local/share/cargo-risczero/toolchains/rust_x86_64-unknown-linux-gnu_r0.1.91.1";

        # Mock rustup for risc0-build's toolchain detection.
        rustup-mock = pkgs.writeShellApplication {
          name = "rustup";
          text = ''
            toolchain="${risc0-toolchain}"
            if [[ "''${1:-}" = "toolchain" ]]; then
              printf 'risc0\t%s\n' "$toolchain"
            elif [[ "''${1:-}" = "+risc0" ]]; then
              printf '%s' "$toolchain/bin/rustc"
            fi
          '';
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo-risczero
            cmake
            cudaPackages.cudatoolkit
            gcc
            git
            jq
            ninja
            openssl
            openssl.dev
            pkg-config
            protobuf
            rust
            rustup-mock
          ];

          shellHook = ''
            export OPENSSL_DIR="${pkgs.openssl.dev}"
            export OPENSSL_LIB_DIR="${pkgs.openssl.out}/lib"
            export OPENSSL_INCLUDE_DIR="${pkgs.openssl.dev}/include"
            export CUDA_HOME="${pkgs.cudaPackages.cudatoolkit}"
          '';

          RUST_BACKTRACE = "1";
        };
      }
    );
}
