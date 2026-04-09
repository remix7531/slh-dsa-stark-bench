{
  description = "SPHINCS+ STARK batch verification PoC";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
    risc0pkgs.url = "github:malda-protocol/risc0pkgs";
    risc0pkgs.inputs.nixpkgs.follows = "nixpkgs";
    risc0pkgs.inputs.rust-overlay.follows = "rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, risc0pkgs }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (import rust-overlay)
            risc0pkgs.overlays.default
          ];
        };

        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };

        rustVersion = pkgs.lib.removePrefix "r0." pkgs.risc0-rust.version;
        arch = {
          x86_64-linux = "x86_64-unknown-linux-gnu";
          aarch64-linux = "aarch64-unknown-linux-gnu";
          aarch64-darwin = "aarch64-apple-darwin";
          x86_64-darwin = "x86_64-apple-darwin";
        }.${system};
        toolchainName = "v${rustVersion}-rust-${arch}";
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            gcc
            git
            jq
            openssl
            openssl.dev
            pkg-config
            protobuf
            r0vm
            risc0-rust
            riscv32-cc
            rust
          ];

          shellHook = ''
            export OPENSSL_DIR="${pkgs.openssl.dev}"
            export OPENSSL_LIB_DIR="${pkgs.openssl.out}/lib"
            export OPENSSL_INCLUDE_DIR="${pkgs.openssl.dev}/include"

            # Set up risc0 toolchain in the location risc0-build expects
            mkdir -p $HOME/.risc0/toolchains/${toolchainName}
            ln -sfn ${pkgs.risc0-rust}/bin $HOME/.risc0/toolchains/${toolchainName}/bin
            ln -sfn ${pkgs.risc0-rust}/lib $HOME/.risc0/toolchains/${toolchainName}/lib
            printf '[default_versions]\nrust = "%s"\n' "${rustVersion}" > $HOME/.risc0/settings.toml

            export LD_LIBRARY_PATH="${pkgs.gcc.cc.lib}/lib:$LD_LIBRARY_PATH"

            export CC_riscv32im_risc0_zkvm_elf=${pkgs.riscv32-cc}/bin/${pkgs.riscv32-cc.targetPrefix}gcc
            export CXX_riscv32im_risc0_zkvm_elf=${pkgs.riscv32-cc}/bin/${pkgs.riscv32-cc.targetPrefix}g++
            export AR_riscv32im_risc0_zkvm_elf=${pkgs.riscv32-cc}/bin/${pkgs.riscv32-cc.targetPrefix}ar
          '';

          RUST_BACKTRACE = "1";
        };
      }
    );
}
