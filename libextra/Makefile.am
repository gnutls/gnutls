AM_CPPFLAGS = -I$(top_srcdir)/crypto -I$(top_srcdir)/gl			\
	-I$(top_srcdir)/lib -I../includes -I$(top_srcdir)/includes	\
	-I$(top_srcdir)/lib/minitasn1 -I$(srcdir)/openpgp		\
	$(LIBGCRYPT_CFLAGS)

if ENABLE_MINITASN1
AM_CPPFLAGS += -I$(top_srcdir)/lib/minitasn1
else
AM_CPPFLAGS += $(LIBTASN1_CFLAGS)
endif

SUBDIRS = 

if ENABLE_OPENPGP
if ENABLE_INCLUDED_OPENCDK
SUBDIRS += opencdk
AM_CPPFLAGS += -I$(srcdir)/opencdk
else
AM_CPPFLAGS += $(LIBOPENCDK_CFLAGS)
endif
SUBDIRS += openpgp
endif

bin_SCRIPTS = libgnutls-extra-config

m4datadir = $(datadir)/aclocal
dist_m4data_DATA = libgnutls-extra.m4

# Pkg-config script.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gnutls-extra.pc
DISTCLEANFILES = $(pkgconfig_DATA)

EXTRA_DIST = gnutls-extra-api.texi

lib_LTLIBRARIES = libgnutls-extra.la

# OpenSSL

libgnutls_openssl_la_LDFLAGS =
if ENABLE_OPENSSL
lib_LTLIBRARIES += libgnutls-openssl.la

libgnutls_openssl_la_SOURCES = gnutls_openssl.c openssl_compat.h	\
	openssl_compat.c

libgnutls_openssl_la_LIBADD = ../lib/libgnutls.la ../crypto/libgc.la

libgnutls_openssl_la_LDFLAGS += -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

if ENABLE_MINITASN1
libgnutls_openssl_la_LIBADD += ../lib/minitasn1/libminitasn1.la
else
libgnutls_openssl_la_LDFLAGS += $(LIBTASN1_LIBS) 
endif
endif

# OpenPGP

libgnutls_extra_la_LIBADD =
libgnutls_extra_la_LDFLAGS =
if ENABLE_OPENPGP
if ENABLE_INCLUDED_OPENCDK
libgnutls_extra_la_LIBADD += opencdk/libminiopencdk.la
else
libgnutls_extra_la_LDFLAGS += $(LIBOPENCDK_LIBS) 
endif
endif

# LZO

LZO_OBJECTS = 
if ENABLE_INCLUDED_LZO
LZO_OBJECTS += lzoconf.h minilzo.h minilzo.c
endif

COBJECTS_EXTRA = gnutls_extra.c

libgnutls_extra_la_LDFLAGS += -export-symbols-regex '^gnutls.*' \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	$(LZO_LIBS)

libgnutls_extra_la_SOURCES = $(COBJECTS_EXTRA) $(LZO_OBJECTS)	\
	gnutls_extra.h

libgnutls_extra_la_LIBADD += ../lib/libgnutls.la ../gl/libgnu.la


gnutls-extra-api.texi: $(COBJECTS_EXTRA)
	@echo "" > gnutls-extra-api.texi
	@for i in $(COBJECTS_EXTRA); do \
		echo -n "Creating documentation for file $$i... " && \
		../doc/scripts/gdoc -texinfo $$i >> gnutls-extra-api.texi && \
		echo "ok"; \
	done

dist-hook: gnutls-extra-api.texi
