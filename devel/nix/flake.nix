# nix build 'path:.?dir=devel/nix#release-tarball'
# inside a clean full checkout with submodules
{
  description = "GnuTLS internal development Nix flake";

  outputs = { self, nixpkgs, flake-utils }:
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        inherit (pkgs) lib;

        src = import ./src.nix { inherit self lib ; };  # must contain .git
        version = import ./version.nix { inherit lib src; };

        rt = pkgs.callPackage ./release-tarball.nix { inherit src version; };

        # tests on release tarball: build it with hand-rolled minimal packaging
        minimal = pkgs.callPackage ./minimal.nix { src = rt; inherit version; };
        # ... and build it the way nixpkgs builds gnutls
        nixpkgs-like = pkgs.gnutls.overrideAttrs { src = rt; inherit version; };
        # ... and build a handful of reverse dependencies with the latter
        revdeps = pkgs.linkFarm "gnutls-revdeps" (
          lib.map (p: {
            inherit (p) name;
            path = p.override { gnutls = nixpkgs-like; };
          }) (with pkgs; [ chrony curlWithGnuTls openconnect tlspool ])
        );
        # ... and build the manual (html/epub/pdf) using it, web-pages -style
        docs = pkgs.callPackage ./docs.nix {
          inherit src version;
          release-tarball = rt;
        };

        devShells = import ./shells.nix { inherit pkgs; };
      in
      {
        packages = {
          release-tarball = rt;
          inherit minimal docs nixpkgs-like revdeps;  # internal; do not rely on
        };
        inherit devShells;
      }
    ));
}
