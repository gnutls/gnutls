EXTRA_DIST = common.h prime.gaa crypt.gaa crypt-gaa.h README.srpcrypt prime-gaa.h \
		README cli.gaa cli-gaa.h serv-gaa.h serv.gaa tls_test.gaa \
		tls_test-gaa.h tests.h gnutls-http-serv
SUBDIRS = srp x509 openpgp

INCLUDES = -I../lib -I../libasn1/lib

bin_PROGRAMS = gnutls-serv gnutls-cli gnutls-srpcrypt gnutls-cli-debug
gnutls_serv_SOURCES = serv-gaa.c serv.c common.c
gnutls_serv_LDADD = ../lib/libgnutls.la ../libextra/libgnutls-extra.la  $(LIBGCRYPT_LIBS) $(LIBOPENCDK_LIBS)
gnutls_srpcrypt_SOURCES = crypt-gaa.c crypt.c
gnutls_srpcrypt_LDADD = ../lib/libgnutls.la ../libextra/libgnutls-extra.la  $(LIBGCRYPT_LIBS) $(LIBOPENCDK_LIBS)
gnutls_cli_SOURCES = cli-gaa.c cli.c common.c 
gnutls_cli_LDADD = ../lib/libgnutls.la ../libextra/libgnutls-extra.la  $(LIBGCRYPT_LIBS) $(LIBOPENCDK_LIBS)
gnutls_cli_debug_SOURCES = tls_test-gaa.c tls_test.c tests.c
gnutls_cli_debug_LDADD = ../lib/libgnutls.la ../libextra/libgnutls-extra.la  $(LIBGCRYPT_LIBS) $(LIBOPENCDK_LIBS)



noinst_PROGRAMS = prime
prime_SOURCES = prime-gaa.c prime.c
prime_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS) $(LIBOPENCDK_LIBS)


crypt-gaa.c: crypt.gaa
	-gaa crypt.gaa -o crypt-gaa.c -i crypt-gaa.h
prime-gaa.c: prime.gaa
	-gaa prime.gaa -o prime-gaa.c -i prime-gaa.h
cli-gaa.c: cli.gaa
	-gaa cli.gaa -o cli-gaa.c -i cli-gaa.h
tls_test-gaa.c: tls_test.gaa
	-gaa tls_test.gaa -o tls_test-gaa.c -i tls_test-gaa.h
serv-gaa.c: serv.gaa
	-gaa serv.gaa -o serv-gaa.c -i serv-gaa.h

