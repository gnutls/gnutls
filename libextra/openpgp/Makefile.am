INCLUDES = -I. -I../ -I../../includes/ -I../../lib -I../../lib/minitasn1 $(LIBOPENCDK_CFLAGS) $(LIBGCRYPT_CFLAGS) $(LIBTASN1_CFLAGS) -I../opencdk
EXTRA_DIST = openpgp.h gnutls_openpgp.h 
noinst_LTLIBRARIES = libpgp.la
libpgp_la_SOURCES = openpgp.c xml.c verify.c extras.c compat.c privkey.c

pgp-api.tex: $(COBJECTS)
	@echo "" > pgp-api.tex
	@for i in $(COBJECTS); \
	do echo -n "Creating documentation for file $$i... " && ../../doc/scripts/gdoc -tex $$i >> pgp-api.tex \
	&& echo "ok"; \
	done

dist-hook: pgp-api.tex
