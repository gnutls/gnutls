INCLUDES = -I../ -I../minitasn1/ -I../../includes/
EXTRA_DIST = dn.h common.h x509.h extensions.h pkcs7.h \
	x509-api.tex compat.h verify.h mpi.h crq.h sign.h

noinst_LTLIBRARIES = libx509.la
lib_LTLIBRARIES = libgnutls-x509.la

COBJECTS1 = crl.c dn.c common.c x509.c extensions.c \
	rfc2818_hostname.c verify.c mpi.c privkey.c pkcs7.c

# Extra stuff that will only be put in gnutls-x509 library.
COBJECTS2 = crq.c xml.c sign.c

COMPAT_OBJECTS = compat.c


libx509_la_SOURCES = $(COBJECTS1) $(COMPAT_OBJECTS)

libgnutls_x509_la_SOURCES = $(COBJECTS2)

libgnutls_extra_la_LIBADD = ../lib/libgnutls.la
libgnutls_x509_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

x509-api.tex: $(COBJECTS1) $(COBJECTS2)
	@echo "" > x509-api.tex
	@for i in $(COBJECTS); \
	do echo -n "Creating documentation for file $$i... " && ../../doc/scripts/gdoc -tex $$i >> x509-api.tex \
	&& echo "ok"; \
	done

dist-hook: x509-api.tex
