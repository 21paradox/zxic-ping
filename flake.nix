{
  # usage:
  # nix develop .#zxic --extra-experimental-features "nix-command flakes"

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # 通用配置
        overlays = [ (import rust-overlay) ];
        basePkgs = import nixpkgs { inherit system overlays; };
        
        rustVersion = "1.89.0";
        rustToolchain = basePkgs.rust-bin.stable.${rustVersion}.default.override {
          extensions = [ "rust-src" ];
          targets = [ "armv7-unknown-linux-musleabi" ];
        };
        
        # 交叉编译配置
        armPkgs = import nixpkgs {
          inherit system overlays;
          crossSystem = { config = "armv7l-unknown-linux-musleabi"; };
        };
        crossGcc = armPkgs.stdenv.cc;
        
        # 共享的构建输入
        commonNativeInputs = [
          rustToolchain
          basePkgs.pkg-config
          crossGcc
          basePkgs.cacert  
          basePkgs.bashInteractive
        ];
        
        # 共享的环境变量
        commonEnv = {
          LANG = "C.UTF-8";
          LC_ALL = "C.UTF-8";
          CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABI_LINKER = "${crossGcc}/bin/armv7l-unknown-linux-musleabi-gcc";
          # CURL_CA_BUNDLE      = "${basePkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
          # CARGO_NET_CAINFO    = "${basePkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
          SSL_CERT_FILE = "${basePkgs.cacert}/etc/ssl/certs/ca-bund";
        };

        # 开发环境
        mkZxicShell = extraInputs: basePkgs.mkShell (commonEnv // {
          nativeBuildInputs = commonNativeInputs ++ ([]);
          buildInputs = [ ];
          
          shellHook = ''
            echo "zxic development environment (ARM cross-compilation)"
            echo "Build: nix build .#zxic"
            export SSL_CERT_FILE="${basePkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
            echo $SSL_CERT_FILE
          '';
        });

      in
      {
        devShells = {
          zxic = mkZxicShell [ ];
          default = mkZxicShell [ ];
        };
      }
    );
}