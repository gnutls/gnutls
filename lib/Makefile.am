INCLUDES = -I../libextra -Iminitasn1/ -I../includes
bin_SCRIPTS = libgnutls-config

m4datadir = $(datadir)/aclocal
m4data_DATA = libgnutls.m4

SUBDIRS = $(MINITASN1_DIR)

EXTRA_DIST = minitasn1 debug.h gnutls_compress.h defines.h gnutls.asn pkix.asn \
	gnutls_cipher.h gnutls_buffers.h gnutls_errors.h gnutls_int.h \
	gnutls_handshake.h gnutls_num.h gnutls_algorithms.h gnutls_dh.h \
	gnutls_kx.h gnutls_hash_int.h gnutls_cipher_int.h gnutls_db.h \
	gnutls_compress_int.h gnutls_session.h gnutls_priority.h gnutls_auth.h \
	auth_anon.h gnutls_extensions.h gnutls_buffer.h \
	gnutls_auth_int.h gnutls_random.h x509_b64.h gnutls_v2_compat.h \
	libgnutls-config.in libgnutls.m4 gnutls.h.in.in gnutls_errors_int.h \
	gnutls_datum.h auth_cert.h gnutls_mpi.h \
	gnutls_pk.h gnutls_record.h gnutls_cert.h \
	gnutls_privkey.h gnutls_constate.h gnutls_global.h x509_verify.h \
	gnutls_sig.h gnutls_mem.h x509_extensions.h gnutls_ui.h \
	gnutls-api.tex io_debug.h ext_max_record.h gnutls_session_pack.h \
	gnutls_alert.h gnutls_str.h gnutls_state.h gnutls_x509.h \
	ext_cert_type.h gnutls_rsa_export.h ext_server_name.h auth_dh_common.h
lib_LTLIBRARIES = libgnutls.la


COBJECTS = gnutls_record.c gnutls_compress.c debug.c \
	gnutls_cipher.c gnutls_buffers.c gnutls_handshake.c gnutls_num.c \
	gnutls_errors.c gnutls_algorithms.c gnutls_dh.c gnutls_kx.c \
	gnutls_priority.c gnutls_hash_int.c gnutls_cipher_int.c \
	gnutls_compress_int.c gnutls_session.c gnutls_db.c x509_b64.c \
	auth_anon.c gnutls_extensions.c gnutls_auth.c gnutls_random.c \
	gnutls_v2_compat.c gnutls_datum.c auth_rsa.c gnutls_session_pack.c \
	gnutls_mpi.c gnutls_pk.c gnutls_cert.c x509_verify.c\
	gnutls_global.c gnutls_privkey.c gnutls_constate.c gnutls_anon_cred.c \
	x509_sig_check.c pkix_asn1_tab.c gnutls_asn1_tab.c gnutls_mem.c \
	x509_extensions.c auth_cert.c gnutls_ui.c gnutls_sig.c auth_dhe.c \
	gnutls_dh_primes.c ext_max_record.c gnutls_alert.c gnutls_int_compat.c \
	gnutls_str.c gnutls_state.c gnutls_x509.c ext_cert_type.c \
	x509_xml.c gnutls_rsa_export.c auth_rsa_export.c rfc2818_hostname.c \
	ext_server_name.c auth_dh_common.c

# Separate so we can create the documentation

libgnutls_la_SOURCES = $(COBJECTS) 

libgnutls_la_LIBADD = $(MINITASN1_OBJECTS)

libgnutls_la_LDFLAGS = $(LIBASN1_LINK) $(LIBGCRYPT_LIBS) \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

pkix_asn1_tab.c: pkix.asn
	-../libtasn1/src/asn1c pkix.asn pkix_asn1_tab.c

gnutls_asn1_tab.c: gnutls.asn
	-../libtasn1/src/asn1c gnutls.asn gnutls_asn1_tab.c

gnutls-api.tex: $(COBJECTS)
	@echo "" > gnutls-api.tex
	@for i in $(COBJECTS); \
	do echo -n "Creating documentation for file $$i... " && ../doc/scripts/gdoc -tex $$i >> gnutls-api.tex \
	&& echo "ok"; \
	done

all-local: gnutls-api.tex
