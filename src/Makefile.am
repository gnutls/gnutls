EXTRA_DIST = port.h crypt.gaa gaa.h README.crypt
INCLUDES = -I../lib
noinst_PROGRAMS = serv cli crypt
serv_SOURCES = serv.c
serv_LDADD = ../lib/libgnutls.la $(GCRYPT_LIBS)
crypt_SOURCES = crypt.c gaaout.c
crypt_LDADD = ../lib/libgnutls.la $(GCRYPT_LIBS)
cli_SOURCES = cli.c
cli_LDADD = ../lib/libgnutls.la $(GCRYPT_LIBS)

