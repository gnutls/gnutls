EXTRA_DIST = TODO README.CVS README.autoconf certtool.cfg \
	gnutls.ps gnutls.pdf gnutls.html
SUBDIRS = tex examples scripts manpages

info_TEXINFOS = gnutls.texi
gnutls_TEXINFOS = gnutls.texi fdl.texi error_codes.texi \
	gnutls-api.texi gnutls-extra-api.texi x509-api.texi pgp-api.texi \
	internals.eps internals.png layers.eps layers.png \
	pgp1.eps pgp1.png x509-1.eps x509-1.png

gnutls.texi: build_api_pgp build_api_lib build_api_x509 build_api_extra examples

build_api_lib:
	cd ../lib && make gnutls-api.texi

build_api_x509:
	cd ../lib/x509 && make x509-api.texi

build_api_pgp:
	cd ../libextra/openpgp && make pgp-api.texi

build_api_extra:
	cd ../libextra && make gnutls-extra-api.texi

examples:
	cd tex && make examples

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

.PHONY: build_api_lib build_api_x509 build_api_pgp build_api_extra
