EXTRA_DIST = common.h crypt.gaa crypt-gaa.h README.srptool \
	README cli.gaa cli-gaa.h serv-gaa.h serv.gaa tls_test.gaa \
	tls_test-gaa.h tests.h gnutls-http-serv list.h certtool-gaa.h \
	certtool.gaa getpass.h certtool-cfg.h

SUBDIRS = srp x509 openpgp cfg

INCLUDES = -I../lib -I../libtasn1/lib -I../includes $(LIBOPENCDK_CFLAGS) -Icfg/

bin_PROGRAMS = gnutls-serv gnutls-cli srptool gnutls-cli-debug certtool
gnutls_serv_SOURCES = serv-gaa.c serv.c common.c
gnutls_serv_LDADD = ../lib/libgnutls.la ../libextra/libgnutls-extra.la $(LIBGCRYPT_LIBS) $(LIBOPENCDK_LIBS) $(SERV_LIBS)
srptool_SOURCES = crypt-gaa.c crypt.c getpass.c
srptool_LDADD = ../lib/libgnutls.la ../libextra/libgnutls-extra.la  $(LIBGCRYPT_LIBS) $(LIBOPENCDK_LIBS)
gnutls_cli_SOURCES = cli-gaa.c cli.c common.c 
gnutls_cli_LDADD = ../lib/libgnutls.la ../libextra/libgnutls-extra.la  $(LIBGCRYPT_LIBS) $(LIBOPENCDK_LIBS) $(SERV_LIBS)
gnutls_cli_debug_SOURCES = tls_test-gaa.c tls_test.c tests.c common.c
gnutls_cli_debug_LDADD = ../lib/libgnutls.la ../libextra/libgnutls-extra.la  $(LIBGCRYPT_LIBS) $(LIBOPENCDK_LIBS) $(SERV_LIBS)


noinst_PROGRAMS = retcodes
retcodes_SOURCES = retcodes.c
retcodes_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)

if HAVE_LIBCFG
certtool_SOURCES = certtool-gaa.c certtool.c prime.c getpass.c certtool-cfg.c
certtool_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS) -lcfg+
else
certtool_SOURCES = certtool-gaa.c certtool.c prime.c getpass.c certtool-cfg.c \
	cfg/cfg+.c cfg/cfgfile.c cfg/cmdline.c cfg/parse.c cfg/props.c \
	cfg/shared.c cfg/platon/str/dynfgets.c cfg/platon/str/strctype.c \
	cfg/platon/str/strdyn.c cfg/platon/str/strplus.c
certtool_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS)
endif



crypt-gaa.c: crypt.gaa
	-gaa crypt.gaa -o crypt-gaa.c -i crypt-gaa.h
certtool-gaa.c: certtool.gaa
	-gaa certtool.gaa -o certtool-gaa.c -i certtool-gaa.h
cli-gaa.c: cli.gaa
	-gaa cli.gaa -o cli-gaa.c -i cli-gaa.h
tls_test-gaa.c: tls_test.gaa
	-gaa tls_test.gaa -o tls_test-gaa.c -i tls_test-gaa.h
serv-gaa.c: serv.gaa
	-gaa serv.gaa -o serv-gaa.c -i serv-gaa.h

