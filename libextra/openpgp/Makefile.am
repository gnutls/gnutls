# source files added here must be added to ../Makefile.am
# to be compiled.

COBJECTS = pgp.c xml.c pgpverify.c extras.c compat.c privkey.c

EXTRA_DIST = openpgp.h gnutls_openpgp.h $(COBJECTS) pgp-api.texi

pgp-api.texi: $(COBJECTS)
	@echo "" > pgp-api.texi
	@for i in ../gnutls_openpgp.c $(COBJECTS); do \
		echo -n "Creating documentation for file $$i... " && \
		../../doc/scripts/gdoc -texinfo $$i >> pgp-api.texi && \
		echo "ok"; \
	done

dist-hook: pgp-api.texi
