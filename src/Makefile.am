EXTRA_DIST = port.h prime.gaa crypt.gaa crypt-gaa.h README.crypt prime-gaa.h README
INCLUDES = -I../lib
noinst_PROGRAMS = serv cli crypt prime
serv_SOURCES = serv.c
serv_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)
crypt_SOURCES = crypt-gaa.c crypt.c
crypt_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)
prime_SOURCES = prime-gaa.c prime.c
prime_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)
cli_SOURCES = cli.c
cli_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)

crypt-gaa.c: crypt.gaa
	gaa crypt.gaa -o crypt-gaa.c -i crypt-gaa.h
prime-gaa.c: prime.gaa
	gaa prime.gaa -o prime-gaa.c -i prime-gaa.h

