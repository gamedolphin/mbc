{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };
        in
        with pkgs;
        {
          devShells.default = mkShell {
            packages = with pkgs; [
              pkg-config
              llvm_18
              llvmPackages_18.bintools-unwrapped
              gnum4

              bpftools
              elfutils
              libpcap
              clang_18
            ];

            shellHook = ''
            '';
          };
        }
      );
}
