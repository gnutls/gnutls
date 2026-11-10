{ lib, src }:

let
  acLines = lib.splitString "\n" (builtins.readFile (src + "/configure.ac"));
  acVersionLine = lib.findFirst (lib.hasPrefix "AC_INIT([GnuTLS],") "" acLines;
  acVersionLineCutOnce = lib.removePrefix "AC_INIT([GnuTLS],[" acVersionLine;
  version = lib.head (lib.splitString "]" acVersionLineCutOnce);
in
  assert version != "";
  version
