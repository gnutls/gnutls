EXTRA_DIST = TODO README.CVS README.autoconf certtool.cfg \
	gnutls.ps gnutls.pdf gnutls.html
SUBDIRS = scripts manpages
if ENABLE_GTK_DOC
SUBDIRS += reference
endif

info_TEXINFOS = gnutls.texi
gnutls_TEXINFOS = gnutls.texi fdl.texi error_codes.texi			\
	gnutls-api.texi gnutls-extra-api.texi x509-api.texi		\
	pgp-api.texi examples/ex-client2.c examples/ex-session-info.c	\
	examples/ex-verify.c examples/ex-cert-select.c			\
	examples/ex-client-resume.c examples/ex-client-srp.c		\
	examples/ex-serv1.c examples/ex-serv-export.c			\
	examples/ex-serv-pgp.c examples/ex-serv-srp.c			\
	examples/ex-alert.c examples/ex-x509-info.c examples/ex-crq.c	\
	examples/ex-pkcs12.c internals.eps internals.png layers.eps	\
	layers.png pgp1.eps pgp1.png x509-1.eps x509-1.png

AM_MAKEINFOHTMLFLAGS = --no-split

../lib/gnutls-api.texi:
	cd ../lib && make gnutls-api.texi

../libextra/gnutls-extra-api.texi:
	cd ../libextra && make gnutls-extra-api.texi

../lib/x509/x509-api.texi:
	cd ../lib/x509 && make x509-api.texi

../libextra/openpgp/pgp-api.texi:
	cd ../libextra/openpgp && make pgp-api.texi

gnutls-api.texi: ../lib/gnutls-api.texi
	-scripts/sort2.pl < ../lib/gnutls-api.texi > gnutls-api.texi

gnutls-extra-api.texi: ../libextra/gnutls-extra-api.texi
	-scripts/sort2.pl < ../libextra/gnutls-extra-api.texi > gnutls-extra-api.texi

x509-api.texi: ../lib/x509/x509-api.texi
	-scripts/sort2.pl < ../lib/x509/x509-api.texi > x509-api.texi

pgp-api.texi: ../libextra/openpgp/pgp-api.texi
	-scripts/sort2.pl < ../libextra/openpgp/pgp-api.texi > pgp-api.texi

error_codes.texi: ../lib/gnutls_errors_int.h ../lib/gnutls_errors.c ../src/errcodes.c
	-../src/errcodes > error_codes.texi
