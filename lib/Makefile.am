include_HEADERS = gnutls.h 
EXTRA_DIST = debug.h gnutls_compress.h defines.h gnutls_plaintext.h gnutls_cipher.h gnutls_buffers.h gnutls_errors.h gnutls_int.h gnutls_handshake.h gnutls_num.h gnutls_algorithms.h gnutls_dh.h gnutls_kx.h
lib_LTLIBRARIES = libgnutls.la
libgnutls_la_SOURCES = gnutls.c gnutls_compress.c debug.c gnutls_plaintext.c gnutls_cipher.c gnutls_buffers.c gnutls_handshake.c gnutls_num.c gnutls_errors.c gnutls_algorithms.c gnutls_dh.c gnutls_kx.c
libgnutls_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
