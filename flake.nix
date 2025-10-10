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

  outputs = { self, nixpkgs, nixpkgs-android, flake-utils, rust-overlay,  ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        armpkgs = import nixpkgs {
          inherit system overlays;
          crossSystem = { config = "armv7l-unknown-linux-musleabi"; };
        };

        rustVersion = "1.89.0";
        rust1 = pkgs.rust-bin.stable.${rustVersion}.default.override {
            extensions = [ "rust-src" "rust-std" ];
            targets = [
             "armv7-unknown-linux-musleabi"
            ];
        };
        
        crossGcc = armpkgs.stdenv.cc;

        # 在 let 块中处理 pkgsCross 属性名
        pkgsCrossNames = pkgs.lib.concatStringsSep "\n" (builtins.attrNames pkgs.pkgsCross);
      in

      {
        # android entry
        devShells.zxic = pkgs.mkShell rec {
          nativeBuildInputs = [
              rust1
              pkgs.pkg-config
           ];
          buildInputs = [];

          LANG = "C.UTF-8";
          LC_ALL = "C.UTF-8";
          PATH = pkgs.lib.makeBinPath [ crossGcc ];

          CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABI_LINKER  = "${crossGcc}/bin/armv7l-unknown-linux-musleabi-gcc";

          # 设置编译器标志
          shellHook = ''
            unset NIX_CFLAGS_COMPILE
            unset NIX_CFLAGS_COMPILE_FOR_BUILD
        
            echo "${pkgsCrossNames}"
            echo "${crossGcc}"
            echo "================================"
          '';
        };

        #devShells.default = pkgs.mkShell {};
      }
    );
}