AM_CPPFLAGS = -I$(top_srcdir)/crypto -I$(top_srcdir)/gl		\
	-I$(top_srcdir)/lib -I$(top_srcdir)/includes -I../includes	\
	-I$(top_srcdir)/libextra/opencdk

noinst_LTLIBRARIES = libgnutls_openpgp.la

COBJECTS = pgp.c xml.c pgpverify.c extras.c compat.c privkey.c

libgnutls_openpgp_la_SOURCES = $(COBJECTS) openpgp.h gnutls_openpgp.h

EXTRA_DIST = pgp-api.texi

pgp-api.texi: $(COBJECTS)
	@echo "" > pgp-api.texi
	@for i in ../gnutls_openpgp.c $(COBJECTS); do \
		echo -n "Creating documentation for file $$i... " && \
		../../doc/scripts/gdoc -texinfo $$i >> pgp-api.texi && \
		echo "ok"; \
	done

dist-hook: pgp-api.texi
