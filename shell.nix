
let moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  nixpkgs = import <nixpkgs> { overlays = [ moz_overlay ]; };
  rustChannel = nixpkgs.latest.rustChannels.stable; in
with nixpkgs;
stdenv.mkDerivation {
  name = "byztimed";
  nativeBuildInputs = [ doxygen pkgconfig rustChannel.rust protobuf openssl ];

  PROTOC = "${protobuf}/bin/protoc";
  PROTOC_INCLUDE = "${protobuf}/include";
}
