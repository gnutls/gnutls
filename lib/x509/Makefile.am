INCLUDES = -I../ -I../minitasn1/ -I../../includes/
EXTRA_DIST = crl.h dn.h common.h x509.h extensions.h pkcs7.h \
	x509-api.tex compat.h

noinst_LTLIBRARIES = libx509.la

COBJECTS = crl.c dn.c common.c x509.c extensions.c \
	pkcs7.c compat.c xml.c rfc2818_hostname.c



libx509_la_SOURCES = $(COBJECTS)

x509-api.tex: $(COBJECTS)
	@echo "" > x509-api.tex
	@for i in $(COBJECTS); \
	do echo -n "Creating documentation for file $$i... " && ../../doc/scripts/gdoc -tex $$i >> x509-api.tex \
	&& echo "ok"; \
	done

all-local: x509-api.tex
