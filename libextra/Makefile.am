INCLUDES = -I../lib -I../includes -I../lib/minitasn1/ $(LIBOPENCDK_CFLAGS) $(LIBGCRYPT_CFLAGS) $(LIBTASN1_CFLAGS) -Iopencdk/ -Iopenpgp/
AM_CFLAGS = -DVERSION=\"gnutls/opencdk\"
bin_SCRIPTS = libgnutls-extra-config
DIST_SUBDIRS = openpgp opencdk

m4datadir = $(datadir)/aclocal
m4data_DATA = libgnutls-extra.m4

if HAVE_LD_VERSION_SCRIPT
  libgnutls_extra_version_script_cmd = -Wl,--version-script=$(srcdir)/libgnutls-extra.vers
else
  libgnutls_extra_version_script_cmd =
endif

EXTRA_DIST = libgnutls-extra.vers \
	openssl_compat.h gnutls-extra-api.texi \
	gnutls_extra.h libgnutls-extra-config.in \
	libgnutls-extra.m4 lzoconf.h minilzo.h


if ENABLE_OPENSSL
lib_LTLIBRARIES = libgnutls-extra.la libgnutls-openssl.la

libgnutls_openssl_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

libgnutls_openssl_la_SOURCES = gnutls_openssl.c openssl_compat.c

libgnutls_openssl_la_LIBADD = \
	../lib/libgnutls.la
else
lib_LTLIBRARIES = libgnutls-extra.la
endif

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

if ENABLE_INCLUDED_LZO
LZO_OBJECTS = minilzo.c
else

LZO_OBJECTS = 
endif


COBJECTS_EXTRA = \
	gnutls_extra.c


libgnutls_extra_la_LDFLAGS = $(libgnutls_extra_version_script_cmd) \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	$(LIBOPENCDK_LIBS) $(LZO_LIBS)

libgnutls_extra_la_SOURCES = $(COBJECTS_EXTRA) $(LZO_OBJECTS) \
	$(PGP_COBJECTS) $(OPENCDK_COBJECTS)

libgnutls_extra_la_LIBADD = ../lib/libgnutls.la


gnutls-extra-api.texi: $(COBJECTS_EXTRA)
	@echo "" > gnutls-extra-api.texi
	@for i in $(COBJECTS_EXTRA); do \
		echo -n "Creating documentation for file $$i... " && \
		../doc/scripts/gdoc -texinfo $$i >> gnutls-extra-api.texi && \
		echo "ok"; \
	done

dist-hook: gnutls-extra-api.texi
