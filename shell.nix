{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    cargo
    rustc
    rust-analyzer
    bpf-linker
    bpftool
    clang
    llvm
    libbpf
    pkg-config
  ];

  shellHook = ''
    echo " Axol Defense Environment (NixOS) Ready!"
  '';
}
