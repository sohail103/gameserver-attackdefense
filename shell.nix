{ pkgs ? import <nixpkgs> {} }:
let
  python = pkgs.python312;
  pythonWithPackages = python.withPackages (ps: with ps; [
    apscheduler
    fastapi
    uvicorn
    jinja2
  ]);
in
pkgs.mkShell {
  name = "ctf-server-env";
  buildInputs = [
    pythonWithPackages
    pkgs.nmap
    pkgs.git
    pkgs.openssl
  ];
  
  shellHook = ''
    echo "nix shell started with fastapi, uvicorn, apscheduler"
  '';
}
