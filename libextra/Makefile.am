DIST_SUBDIRS = openpgp opencdk

INCLUDES = -I$(top_srcdir)/crypto -I$(top_srcdir)/gl -I$(top_srcdir)/lib -I../includes -I$(top_srcdir)/includes -I$(top_srcdir)/lib/minitasn1 $(LIBOPENCDK_CFLAGS) $(LIBGCRYPT_CFLAGS) $(LIBTASN1_CFLAGS) -I$(srcdir)/opencdk -I$(srcdir)/openpgp

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

if ENABLE_OPENSSL
lib_LTLIBRARIES += libgnutls-openssl.la

libgnutls_openssl_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

libgnutls_openssl_la_SOURCES = gnutls_openssl.c openssl_compat.h	\
	openssl_compat.c

libgnutls_openssl_la_LIBADD = ../lib/libgnutls.la ../crypto/libgc.la

if ENABLE_MINITASN1
libgnutls_openssl_la_LIBADD += ../lib/minitasn1/libminitasn1.la
else
libgnutls_openssl_la_LDFLAGS += $(LIBTASN1_LIBS) 
endif
endif

# OpenPGP

if ENABLE_OPENPGP
PGP_COBJECTS = gnutls_openpgp.c openpgp/xml.c \
	openpgp/pgpverify.c openpgp/pgp.c \
	openpgp/extras.c openpgp/compat.c openpgp/privkey.c

if ENABLE_INCLUDED_OPENCDK
SUBDIRS = openpgp opencdk

OPENCDK_COBJECTS = opencdk/new-packet.c opencdk/read-packet.c opencdk/write-packet.c \
	opencdk/main.c 	opencdk/verify.c opencdk/armor.c \
	opencdk/sig-check.c opencdk/sign.c opencdk/keydb.c \
        opencdk/keylist.c opencdk/seskey.c opencdk/pubkey.c opencdk/misc.c \
	opencdk/encrypt.c opencdk/trustdb.c opencdk/kbnode.c \
	opencdk/compress.c opencdk/plaintext.c opencdk/cipher.c \
	opencdk/sym-cipher.c opencdk/stream.c opencdk/keyserver.c \
	opencdk/keygen.c opencdk/md.c
else
SUBDIRS = openpgp
OPENCDK_COBJECTS = 
endif

endif

# LZO

LZO_OBJECTS = 
if ENABLE_INCLUDED_LZO
LZO_OBJECTS += lzoconf.h minilzo.h minilzo.c
endif

COBJECTS_EXTRA = gnutls_extra.c

libgnutls_extra_la_LDFLAGS = -export-symbols-regex '^gnutls.*' \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	$(LIBOPENCDK_LIBS) $(LZO_LIBS)

libgnutls_extra_la_SOURCES = $(COBJECTS_EXTRA) $(LZO_OBJECTS) \
	$(PGP_COBJECTS) $(OPENCDK_COBJECTS) gnutls_extra.h

libgnutls_extra_la_LIBADD = ../lib/libgnutls.la ../gl/libgnu.la


gnutls-extra-api.texi: $(COBJECTS_EXTRA)
	@echo "" > gnutls-extra-api.texi
	@for i in $(COBJECTS_EXTRA); do \
		echo -n "Creating documentation for file $$i... " && \
		../doc/scripts/gdoc -texinfo $$i >> gnutls-extra-api.texi && \
		echo "ok"; \
	done

dist-hook: gnutls-extra-api.texi
