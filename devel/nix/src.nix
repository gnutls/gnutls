{ self, lib }:

let
  repoRoot =
    assert lib.hasSuffix "/devel/nix" self;
    lib.removeSuffix "/devel/nix" self;
in
  # a simple guard against using this flake without ?dir=devel/nix
  lib.throwIfNot
    (builtins.pathExists (repoRoot + "/lib/includes/gnutls/gnutls.h.in"))
    "do not use directly, use path:...?dir=devel/nix"
  # building needs .git for AUTHORS/Changelog, so we have to build through path:
  lib.throwIfNot
    (builtins.pathExists (repoRoot + "/.git/HEAD"))
    "build from a full git checkout"
  repoRoot
