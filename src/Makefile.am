EXTRA_DIST = common.h prime.gaa crypt.gaa crypt-gaa.h README.srpcrypt prime-gaa.h \
		README cli.gaa cli-gaa.h serv-gaa.h serv.gaa
SUBDIRS = srp x509 openpgp

INCLUDES = -I../lib

noinst_PROGRAMS = serv cli srpcrypt prime asn1c CertificateExample CrlExample
serv_SOURCES = serv.c common.c serv-gaa.c
serv_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)
srpcrypt_SOURCES = crypt-gaa.c crypt.c
srpcrypt_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)
prime_SOURCES = prime-gaa.c prime.c
prime_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)
cli_SOURCES = cli.c common.c cli-gaa.c
cli_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)

CertificateExample_SOURCES = CertificateExample.c  
CertificateExample_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)
CrlExample_SOURCES = CrlExample.c  
CrlExample_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)

asn1c_SOURCES = asn1c.c
asn1c_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)

crypt-gaa.c: crypt.gaa
	gaa crypt.gaa -o crypt-gaa.c -i crypt-gaa.h
prime-gaa.c: prime.gaa
	gaa prime.gaa -o prime-gaa.c -i prime-gaa.h
cli-gaa.c: cli.gaa
	gaa cli.gaa -o cli-gaa.c -i cli-gaa.h
serv-gaa.c: serv.gaa
	gaa serv.gaa -o serv-gaa.c -i serv-gaa.h

