include_HEADERS = gnutls.h 
EXTRA_DIST = debug.h gnutls_compress.h defines.h gnutls_plaintext.h gnutls_cipher.h gnutls_buffers.h
lib_LTLIBRARIES = libgnutls.la
libgnutls_la_SOURCES = gnutls.c gnutls_compress.c debug.c gnutls_plaintext.c gnutls_cipher.c gnutls_buffers.c
libgnutls_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
bin_PROGRAMS = test
test_SOURCES = test.c
test_LDADD = libgnutls.la -lgcrypt -lmhash

