INCLUDES = -I../lib -I../includes -I../lib/minitasn1/
bin_SCRIPTS = libgnutls-extra-config
DIST_SUBDIRS = openpgp
SUBDIRS = openpgp

m4datadir = $(datadir)/aclocal
m4data_DATA = libgnutls-extra.m4

if HAVE_LD_VERSION_SCRIPT
  libgnutls_extra_version_script_cmd = -Wl,--version-script=$(srcdir)/libgnutls-extra.vers
else
  libgnutls_extra_version_script_cmd =
endif

EXTRA_DIST = ext_srp.h gnutls_srp.h libgnutls-extra.vers \
	auth_srp.h auth_srp_passwd.h \
	gnutls-extra-api.tex gnutls_extra.h libgnutls-extra-config.in \
	libgnutls-extra.m4 lzoconf.h minilzo.h


lib_LTLIBRARIES = libgnutls-extra.la

COBJECTS_EXTRA = ext_srp.c \
	gnutls_srp.c auth_srp.c auth_srp_passwd.c auth_srp_sb64.c \
	gnutls_extra.c gnutls_openssl.c \
	auth_srp_rsa.c

libgnutls_extra_la_LDFLAGS = $(libgnutls_extra_version_script_cmd) \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	$(LIBOPENCDK_LIBS) $(LZO_LINK)
libgnutls_extra_la_LIBADD = $(LZO_OBJECTS) ../lib/libgnutls.la
libgnutls_extra_la_DEPENDENCIES = $(LZO_OBJECTS)

libgnutls_extra_la_SOURCES = $(COBJECTS_EXTRA) 

libgnutls_extra_la_LIBADD = openpgp/openpgp.lo openpgp/xml.lo openpgp/gnutls_openpgp.lo

EXTRA_libgnutls_extra_la_SOURCES = minilzo.c

gnutls-extra-api.tex: $(COBJECTS_EXTRA)
	@echo "" > gnutls-extra-api.tex
	@for i in $(COBJECTS_EXTRA); \
	do echo -n "Creating documentation for file $$i... " && ../doc/scripts/gdoc -tex $$i >> gnutls-extra-api.tex \
	&& echo "ok"; \
	done

dist-hook: gnutls-extra-api.tex 
