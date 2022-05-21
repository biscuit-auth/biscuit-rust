{ pkgs ? import <nixpkgs> {}}: with pkgs;

mkShell {
  buildInputs = [
    openssl
    rustup
    pkg-config
    zlib
  ];
}
