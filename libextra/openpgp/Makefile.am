INCLUDES = -I../ -I../../includes/
EXTRA_DIST = openpgp.h

noinst_LTLIBRARIES = libpgp.la

COBJECTS = openpgp.c xml.c gnutls_openpgp.c

libx509_la_SOURCES = $(COBJECTS)

pgp-api.tex: $(COBJECTS)
	@echo "" > pgp-api.tex
	@for i in $(COBJECTS); \
	do echo -n "Creating documentation for file $$i... " && ../../doc/scripts/gdoc -tex $$i >> pgp-api.tex \
	&& echo "ok"; \
	done

dist-hook: pgp-api.tex
