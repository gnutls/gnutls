# nix develop ./devel/nix (or #ccache / #sccache)
{ pkgs }:
with pkgs;
let
  base = [
    # bootstrap + autotools (gtk-doc provides gtkdocize, needed by bootstrap)
    autoconf automake bison gettext git gperf libtool perl pkg-config which
    # configure requirements
    gmp nettle p11-kit libtasn1 libidn2 libunistring unbound unbound.lib
    brotli zlib zstd libev
    # test dependencies
    openssl
    # maintainer tools
    libabigail clang-tools yq-go gitlab-ci-local
    # docs
    gtk-doc texinfo
    # misc
    diffutils file gnutar python3 xz
  ];

  cached = name: mkShell {
    packages = base ++ [ pkgs.${name} ];
    postHook = "export CC=\"${name} gcc\" CXX=\"${name} g++\"";
  };
in
{
  default = mkShell { packages = base; };
  ccache = cached "ccache";
  sccache = cached "sccache";
}
