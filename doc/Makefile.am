EXTRA_DIST = TODO README.CVS README.autoconf certtool.cfg
SUBDIRS = tex examples scripts manpages

info_TEXINFOS = gnutls.texi
gnutls_TEXINFOS = gnutls.texi fdl.texi error_codes.texi \
	gnutls-api.texi gnutls-extra-api.texi x509-api.texi pgp-api.texi \
	internals.eps internals.png layers.eps layers.png \
	pgp1.eps pgp1.png x509-1.eps x509-1.png

error_codes.texi: ../lib/gnutls_errors_int.h ../lib/gnutls_errors.c ../src/errcodes.c
	-../src/errcodes > error_codes.texi

gnutls-api.texi: ../lib/gnutls-api.texi
	-scripts/sort2.pl < ../lib/gnutls-api.texi > gnutls-api.texi

gnutls-extra-api.texi: ../libextra/gnutls-extra-api.texi
	-scripts/sort2.pl < ../libextra/gnutls-extra-api.texi > gnutls-extra-api.texi

x509-api.texi: ../lib/x509/x509-api.texi
	-scripts/sort2.pl < ../lib/x509/x509-api.texi > x509-api.texi

pgp-api.texi: ../libextra/openpgp/pgp-api.texi
	-scripts/sort2.pl < ../libextra/openpgp/pgp-api.texi > pgp-api.texi
