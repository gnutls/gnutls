# gnutls.pdf/gnutls.epub are not part of the release tarball,
# so there's no point building it there.
# yet we'd better not break the web-pages `pages` CI job, so test that here,
# mirroring what it does.

{ runCommand, runCommandCC
# source of the entire repository, including .git, see flake.nix / src.nix
, src
# the release tarball to use for building the docs, see release-tarball.nix
, release-tarball
# autodetected version, see version.nix
, version
# SOURCE_DATE_EPOCH / unpacking the tarball
, git, xz
# configure + build requirements (same as release-tarball.nix)
, pkg-config, perl, python3, gettext, texinfo
# gnutls dependencies probed by configure
, gmp, nettle, libtasn1, p11-kit, libidn2, libunistring, unbound
# compressors used by gnutls
, brotli, zlib, zstd
# gnutls.pdf (doc/latex)
, ghostscript
, texliveSmall
# gnutls.epub (dbtoepub from docbook-xsl; uses xmllint and zip internally)
, ruby, docbook_xsl, docbook_xml_dtd_43, docbook_xml_dtd_45, gtk-doc
, libxml2, libxslt, zip
}:

let
  # wrap it so it becomes executable
  dbtoepub = runCommand "dbtoepub" {} ''
    install -d $out/bin
    install -m 0755 /dev/stdin $out/bin/dbtoepub <<\EOF
    #!/bin/sh
    ${ruby}/bin/ruby ${docbook_xsl}/share/xml/docbook-xsl/epub/bin/dbtoepub "$@"
    EOF
  '';

in
runCommandCC "gnutls-${version}-webdocs" {
  nativeBuildInputs = [
    git xz pkg-config perl python3 gettext texinfo gtk-doc
    dbtoepub ghostscript libxml2.bin libxslt.bin zip
    docbook_xml_dtd_43 docbook_xml_dtd_45 docbook_xsl
    (texliveSmall.withPackages (ps: with ps; [
      collection-basic collection-latex collection-latexrecommended
      eurosym fancyhdr fancyvrb float framed geometry
      hyperref listings morefloats parskip quotchap supertabular xcolor
      bookman palatino
    ]))
  ];

  buildInputs = [
    gmp nettle libtasn1 p11-kit libidn2 libunistring unbound unbound.lib
    brotli zlib zstd
  ];

} ''
  export HOME=$TMPDIR  # texlive wants to write to $HOME
  git config --global --add safe.directory "${src}"  # store copy owner is off
  export SOURCE_DATE_EPOCH=$(cd ${src} && git log -1 --format=%ct)

  tar xf ${release-tarball}; cd gnutls-${version}  # unpackPhase substitute

  # use git doc scripts, see web-pages `pages` CI job
  cp ${src}/doc/scripts/*.pl doc/scripts/
  cp ${src}/doc/scripts/mytexi2latex doc/scripts/
  cp ${src}/doc/latex/*.tex doc/latex/
  cp ${src}/doc/latex/*.bib doc/latex/
  cp ${src}/doc/gnutls-logo.pdf doc/
  cp ${src}/doc/epub.texi doc/
  sed -i 's/pdflatex/pdflatex -shell-escape/g' doc/latex/Makefile.in

  patchShebangs doc/scripts/gdoc doc/scripts/*.pl cligen/*.py

  ./configure --disable-tests --disable-manpages --enable-gtk-doc

  touch -d "@$SOURCE_DATE_EPOCH" doc/gnutls.texi
  make -j$(nproc) -C doc stamp-vti

  make -j$(nproc)
  make htmldir=public web  # htmldir must be relative

  for f in public/manual/gnutls.{html,epub,pdf}; do
    [[ -s "$f" ]] || { echo "error: $f missing or empty" >&2; exit 1; }
  done

  mkdir -p $out
  mv public/* $out/
''
