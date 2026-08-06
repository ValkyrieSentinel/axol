{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    bpf-linker
    clang
    llvm
    libbpf
    pkg-config
  ];

  shellHook = ''
    export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
    echo " Axol Environment Ready! "
  '';
}
