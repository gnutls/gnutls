EXTRA_DIST = common.h prime.gaa crypt.gaa crypt-gaa.h README.srpcrypt prime-gaa.h \
		README cli.gaa cli-gaa.h serv-gaa.h serv.gaa tls_test.gaa \
		tls_test-gaa.h tests.h gnutls-http-serv list.h certtool-gaa.h
SUBDIRS = srp x509 openpgp

INCLUDES = -I../lib -I../libtasn1/lib -I../includes

bin_PROGRAMS = gnutls-serv gnutls-cli gnutls-srpcrypt gnutls-cli-debug certtool
gnutls_serv_SOURCES = serv-gaa.c serv.c common.c
gnutls_serv_LDADD = ../lib/libgnutls.la ../libextra/libgnutls-extra.la $(LIBGCRYPT_LIBS) $(LIBOPENCDK_LIBS) $(SERV_LIBS)
gnutls_srpcrypt_SOURCES = crypt-gaa.c crypt.c
gnutls_srpcrypt_LDADD = ../lib/libgnutls.la ../libextra/libgnutls-extra.la  $(LIBGCRYPT_LIBS) $(LIBOPENCDK_LIBS)
gnutls_cli_SOURCES = cli-gaa.c cli.c common.c 
gnutls_cli_LDADD = ../lib/libgnutls.la ../libextra/libgnutls-extra.la  $(LIBGCRYPT_LIBS) $(LIBOPENCDK_LIBS)
gnutls_cli_debug_SOURCES = tls_test-gaa.c tls_test.c tests.c common.c
gnutls_cli_debug_LDADD = ../lib/libgnutls.la ../libextra/libgnutls-extra.la  $(LIBGCRYPT_LIBS) $(LIBOPENCDK_LIBS)


noinst_PROGRAMS = prime retcodes
prime_SOURCES = prime-gaa.c prime.c
prime_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)
retcodes_SOURCES = retcodes.c
retcodes_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)

certtool_SOURCES = certtool-gaa.c certtool.c
certtool_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)


crypt-gaa.c: crypt.gaa
	-gaa crypt.gaa -o crypt-gaa.c -i crypt-gaa.h
prime-gaa.c: prime.gaa
	-gaa prime.gaa -o prime-gaa.c -i prime-gaa.h
certtool-gaa.c: certtool.gaa
	-gaa certtool.gaa -o certtool-gaa.c -i certtool-gaa.h
cli-gaa.c: cli.gaa
	-gaa cli.gaa -o cli-gaa.c -i cli-gaa.h
tls_test-gaa.c: tls_test.gaa
	-gaa tls_test.gaa -o tls_test-gaa.c -i tls_test-gaa.h
serv-gaa.c: serv.gaa
	-gaa serv.gaa -o serv-gaa.c -i serv-gaa.h

