INCLUDES = -I../ -I../minitasn1/ -I../../includes/
EXTRA_DIST = dn.h common.h x509.h extensions.h pkcs7.h \
	x509-api.tex compat.h verify.h mpi.h crq.h sign.h pkcs5.h \
	privkey.h pkcs12.h rc2.h rfc2818.h dsa.h

noinst_LTLIBRARIES = libx509.la
#lib_LTLIBRARIES = libgnutls-x509.la

COBJECTS = crl.c dn.c common.c x509.c extensions.c \
	rfc2818_hostname.c verify.c mpi.c privkey.c pkcs7.c \
	crq.c xml.c sign.c pkcs5.c privkey_pkcs8.c pkcs12.c \
	pkcs12_bag.c pkcs12_encr.c rc2.c x509_write.c crl_write.c dsa.c

COMPAT_OBJECTS = compat.c


libx509_la_SOURCES = $(COBJECTS) $(COMPAT_OBJECTS)

#libgnutls_x509_la_SOURCES = $(COBJECTS2)

#libgnutls_x509_la_LIBADD = ../libgnutls.la
#libgnutls_x509_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

x509-api.tex: $(COBJECTS)
	@echo "" > x509-api.tex
	@for i in $(COBJECTS); \
	do echo -n "Creating documentation for file $$i... " && ../../doc/scripts/gdoc -tex $$i >> x509-api.tex \
	&& echo "ok"; \
	done

dist-hook: x509-api.tex
