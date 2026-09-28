{ stdenv
# source of the release tarball, see flake.nix
, src
# autodetected version, see version.nix
, version
# configure
, pkg-config
# manpages
, perl, texinfo
# translations
, gettext
# dependencies
, gmp, libidn2, libtasn1, libunistring, nettle, p11-kit, unbound, zlib
}:

stdenv.mkDerivation {
  pname = "gnutls";
  inherit version src;

  nativeBuildInputs = [
    # configure
    pkg-config
    # man pages (texinfo's xml2man)
    perl texinfo
    # translations in po/
    gettext
  ];
  buildInputs = [
    gmp libidn2 libtasn1 libunistring nettle p11-kit unbound zlib
  ];
}
