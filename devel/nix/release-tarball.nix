{ runCommand, runCommandCC
# source of the entire repository, including .git, see flake.nix / src.nix
, src
# autodetected version, see version.nix
, version
# bootstrap / autotools
, autoconf, automake, bison, gettext, git, gperf, libtool, perl, pkg-config
, which
# generating the tarball itself
, gnutar, xz
# configure requirements
, gmp, nettle, libtasn1, p11-kit, libidn2, libunistring, unbound
# compressors used by gnutls
, brotli, zlib, zstd
# misc dependencies required for the release tarball specifically
, docbook_xml_dtd_43, docbook_xml_dtd_45, docbook_xsl, gtk-doc, python3, texinfo
}:

let
  reproducibleTar = runCommand "reproducible-tar" {} ''
    mkdir -p $out/bin
    cat > $out/bin/tar <<'EOF'
    #!/bin/sh
    exec ${gnutar}/bin/tar "$@" --sort=name --mtime=@$SOURCE_DATE_EPOCH \
      --owner=0 --group=0 --numeric-owner
    EOF
    chmod +x $out/bin/tar
  '';

in
  runCommandCC "gnutls-${version}.tar.xz" {
    inherit src;

    nativeBuildInputs = [
      reproducibleTar xz
      # bootstrap / autotools
      autoconf automake bison gettext git gperf libtool perl pkg-config which
      # misc dependencies required for the release tarball specifically
      docbook_xml_dtd_43 docbook_xml_dtd_45 docbook_xsl gtk-doc python3 texinfo
    ];

    buildInputs = [
      gmp nettle libtasn1 p11-kit libidn2 libunistring unbound unbound.lib
      brotli zlib zstd
    ];

  } ''
    cp -r ${src}/. .; chmod -R u+w .  # unpackPhase equivalent

    git merge-base --is-ancestor 8aef5fff2e54b67c694fa4ef9190cbedf1ff00c1 HEAD \
      || { echo "error: incomplete .git history: can't reach 8aef5ff"; exit 1; }

    export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

    patchShebangs doc/scripts/gdoc doc/scripts/*.pl cligen/*.py

    SUBMODULE_NOFETCH=1 ./bootstrap

    # https://github.com/autoconf-archive/autoconf-archive/pull/323
    dline=$(grep -m1 '^# from AX_AM_MACROS_STATIC on ' aminclude_static.am)
    substituteInPlace aminclude_static.am Makefile.in \
      --replace-fail "$dline" '# from AX_AM_MACROS_STATIC'

    substituteInPlace cfg.mk \
      --replace-fail '--since="2014 November 07"' '--since="2014-11-07 00:00:00 +0000"'

    CFLAGS="-std=c99 -O2 -g" ./configure \
      --disable-gcc-warnings \
      --prefix=/usr --libdir=/usr/lib64 \
      --disable-cxx \
      --disable-non-suiteb-curves \
      --enable-gtk-doc \
      --disable-full-test-suite \
      --disable-maintainer-mode

    touch -d "@$SOURCE_DATE_EPOCH" doc/gnutls.texi
    make -j$(nproc) -C doc stamp-vti

    # gnutls.pdf/gnutls.epub are built separately, see docs.nix
    make -j$(nproc)
    make -j$(nproc) -C doc gnutls.html
    make -j$(nproc) -C doc/reference html

    # run this check separately while the shebangs are patched
    make -C doc/manpages compare-makefile
    # disable it so that it won't run as part of make dist
    substituteInPlace Makefile \
      --replace-fail '$(MAKE) -C doc/manpages compare-makefile' \
                     'echo skipping manpages compare-makefile'

    # restore shebangs before make dist
    cp ${src}/doc/scripts/gdoc ${src}/doc/scripts/*.pl doc/scripts/
    cp ${src}/cligen/*.py cligen/

    make -j$(nproc) dist
    cp gnutls-${version}.tar.xz $out
  ''
