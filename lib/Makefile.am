include_HEADERS = gnutls.h 
bin_SCRIPTS = libgnutls-config

m4datadir = $(datadir)/aclocal
m4data_DATA = libgnutls.m4

EXTRA_DIST = debug.h gnutls_compress.h defines.h gnutls_plaintext.h \
	gnutls_cipher.h gnutls_buffers.h gnutls_errors.h gnutls_int.h \
	gnutls_handshake.h gnutls_num.h gnutls_algorithms.h gnutls_dh.h \
	gnutls_kx.h gnutls_hash_int.h gnutls_cipher_int.h gnutls_db.h \
	gnutls_compress_int.h gnutls_session.h gnutls_priority.h gnutls_auth.h \
	auth_anon.h auth_dhe_dss.h gnutls_extensions.h ext_srp.h \
	gnutls_auth_int.h crypt_bcrypt.h gnutls_random.h crypt_srpsha1.h \
	cert_b64.h gnutls_srp.h auth_srp.h auth_srp_passwd.h gnutls_v2_compat.h \
	crypt.h libgnutls-config.in libgnutls.m4 gnutls.h.in gnutls_errors_int.h
lib_LTLIBRARIES = libgnutls.la
libgnutls_la_SOURCES = gnutls.c gnutls_compress.c debug.c gnutls_plaintext.c \
	gnutls_cipher.c gnutls_buffers.c gnutls_handshake.c gnutls_num.c \
	gnutls_errors.c gnutls_algorithms.c gnutls_dh.c gnutls_kx.c \
	gnutls_priority.c gnutls_hash_int.c gnutls_cipher_int.c \
	gnutls_compress_int.c gnutls_session.c gnutls_db.c cert_b64.c \
	auth_anon.c auth_dhe_dss.c gnutls_extensions.c ext_srp.c gnutls_auth.c \
	crypt_bcrypt.c crypt.c gnutls_random.c crypt_srpsha1.c gnutls_srp.c \
	auth_srp.c auth_srp_passwd.c gnutls_v2_compat.c auth_srp_sb64.c
libgnutls_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
