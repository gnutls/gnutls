# source files added here must be added to ../Makefile.am
# to be compiled.

COBJECTS = pgp.c xml.c pgpverify.c extras.c compat.c privkey.c

EXTRA_DIST = openpgp.h gnutls_openpgp.h $(COBJECTS)

pgp-api.tex: $(COBJECTS)
	@echo "" > pgp-api.tex
	@for i in $(COBJECTS); \
	do echo -n "Creating documentation for file $$i... " && ../../doc/scripts/gdoc -tex $$i >> pgp-api.tex \
	&& echo "ok"; \
	done

dist-hook: pgp-api.tex
