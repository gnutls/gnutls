INCLUDES = -I../ -I../../includes/ -I../../lib
EXTRA_DIST = openpgp.h gnutls_openpgp.h

noinst_LTLIBRARIES = libpgp.la

COBJECTS = openpgp.c xml.c verify.c extras.c compat.c

libpgp_la_SOURCES = $(COBJECTS)

pgp-api.tex: $(COBJECTS)
	@echo "" > pgp-api.tex
	@for i in $(COBJECTS); \
	do echo -n "Creating documentation for file $$i... " && ../../doc/scripts/gdoc -tex $$i >> pgp-api.tex \
	&& echo "ok"; \
	done

dist-hook: pgp-api.tex
