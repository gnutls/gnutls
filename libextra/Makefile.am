INCLUDES = -I../lib -I../libtasn1/lib/
include_HEADERS = extra.h openssl.h
bin_SCRIPTS = libgnutls-extra-config

m4datadir = $(datadir)/aclocal
m4data_DATA = libgnutls-extra.m4

EXTRA_DIST = ext_srp.h crypt_bcrypt.h crypt_srpsha1.h gnutls_srp.h \
	auth_srp.h auth_srp_passwd.h crypt.h gnutls_openpgp.h \
	gnutls-extra-api.tex gnutls_extra.h libgnutls-extra-config.in \
	libgnutls-extra.m4

lib_LTLIBRARIES = libgnutls-extra.la


COBJECTS_EXTRA = crypt_bcrypt.c crypt.c crypt_srpsha1.c ext_srp.c \
	gnutls_srp.c auth_srp.c auth_srp_passwd.c auth_srp_sb64.c \
	gnutls_openpgp.c gnutls_extra.c

libgnutls_extra_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

libgnutls_extra_la_SOURCES = $(COBJECTS_EXTRA) 

gnutls-extra-api.tex: $(COBJECTS_EXTRA)
	@echo "" > gnutls-extra-api.tex
	@for i in $(COBJECTS_EXTRA); \
	do echo -n "Creating documentation for file $$i... " && ../doc/scripts/gdoc -tex $$i >> gnutls-extra-api.tex \
	&& echo "ok"; \
	done

all-local: gnutls-extra-api.tex 
