INCLUDES = -I../libextra -Iminitasn1/ -I../libextra/openpgp/ -I../libextra/opencdk -Ix509/ -I../includes $(LIBOPENCDK_CFLAGS) $(LIBTASN1_CFLAGS) $(LIBGCRYPT_CFLAGS)
bin_SCRIPTS = libgnutls-config

m4datadir = $(datadir)/aclocal
m4data_DATA = libgnutls.m4

if HAVE_LD_VERSION_SCRIPT
  libgnutls_version_script_cmd = -Wl,--version-script=$(srcdir)/libgnutls.vers
else
  libgnutls_version_script_cmd =
endif

DIST_SUBDIRS = minitasn1 x509
if ENABLE_MINITASN1
SUBDIRS = minitasn1 x509
MINITASN1_COBJECTS = minitasn1/decoding.c minitasn1/gstr.c minitasn1/errors.c \
	minitasn1/parser_aux.c minitasn1/structure.c minitasn1/element.c \
	minitasn1/coding.c
else
SUBDIRS = x509
MINITASN1_COBJECTS = 
endif

EXTRA_DIST = debug.h gnutls_compress.h defines.h gnutls.asn pkix.asn \
	gnutls_cipher.h gnutls_buffers.h gnutls_errors.h gnutls_int.h \
	gnutls_handshake.h gnutls_num.h gnutls_algorithms.h gnutls_dh.h \
	gnutls_kx.h gnutls_hash_int.h gnutls_cipher_int.h gnutls_db.h \
	gnutls_compress_int.h gnutls_session.h gnutls_priority.h gnutls_auth.h \
	auth_anon.h gnutls_extensions.h gnutls_buffer.h libgnutls.vers \
	gnutls_auth_int.h gnutls_random.h x509_b64.h gnutls_v2_compat.h \
	libgnutls-config.in libgnutls.m4 gnutls.h.in.in gnutls_errors_int.h \
	gnutls-api.tex gnutls-api.texi gnutls_datum.h auth_cert.h gnutls_mpi.h \
	gnutls_pk.h gnutls_record.h gnutls_cert.h \
	gnutls_constate.h gnutls_global.h strfile.h \
	gnutls_sig.h gnutls_mem.h gnutls_ui.h \
	io_debug.h ext_max_record.h gnutls_session_pack.h \
	gnutls_alert.h gnutls_str.h gnutls_state.h gnutls_x509.h \
	ext_cert_type.h gnutls_rsa_export.h ext_server_name.h auth_dh_common.h \
	ext_srp.h gnutls_srp.h auth_srp.h auth_srp_passwd.h 
lib_LTLIBRARIES = libgnutls.la

X509_COBJECTS = x509/crl.c x509/dn.c x509/common.c x509/x509.c x509/extensions.c \
	x509/dsa.c x509/rfc2818_hostname.c x509/verify.c x509/mpi.c \
	x509/privkey.c x509/pkcs7.c x509/crq.c x509/xml.c x509/sign.c x509/pkcs5.c \
	x509/privkey_pkcs8.c x509/pkcs12.c x509/pkcs12_bag.c x509/pkcs12_encr.c \
	x509/x509_write.c x509/crl_write.c x509/compat.c

SRP_COBJECTS = ext_srp.c gnutls_srp.c auth_srp.c auth_srp_passwd.c \
	auth_srp_sb64.c auth_srp_rsa.c

COBJECTS = gnutls_record.c gnutls_compress.c debug.c \
	gnutls_cipher.c gnutls_buffers.c gnutls_handshake.c gnutls_num.c \
	gnutls_errors.c gnutls_algorithms.c gnutls_dh.c gnutls_kx.c \
	gnutls_priority.c gnutls_hash_int.c gnutls_cipher_int.c \
	gnutls_compress_int.c gnutls_session.c gnutls_db.c x509_b64.c \
	auth_anon.c gnutls_extensions.c gnutls_auth.c gnutls_random.c \
	gnutls_v2_compat.c gnutls_datum.c auth_rsa.c gnutls_session_pack.c \
	gnutls_mpi.c gnutls_pk.c gnutls_cert.c \
	gnutls_global.c gnutls_constate.c gnutls_anon_cred.c \
	pkix_asn1_tab.c gnutls_asn1_tab.c gnutls_mem.c \
	auth_cert.c gnutls_ui.c gnutls_sig.c auth_dhe.c \
	gnutls_dh_primes.c ext_max_record.c gnutls_alert.c gnutls_int_compat.c \
	gnutls_str.c gnutls_state.c gnutls_x509.c ext_cert_type.c \
	gnutls_rsa_export.c auth_rsa_export.c \
	ext_server_name.c auth_dh_common.c \
	strnstr.c 

# Separate so we can create the documentation

libgnutls_la_SOURCES = $(COBJECTS) $(X509_COBJECTS) $(MINITASN1_COBJECTS) $(SRP_COBJECTS)

libgnutls_la_LDFLAGS = $(LIBTASN1_LIBS) $(LIBGCRYPT_LIBS) \
	$(libgnutls_version_script_cmd) \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

pkix_asn1_tab.c: pkix.asn
	-asn1Parser pkix.asn pkix_asn1_tab.c

gnutls_asn1_tab.c: gnutls.asn
	-asn1Parser gnutls.asn gnutls_asn1_tab.c

gnutls-api.tex gnutls-api.texi: $(COBJECTS)
	@echo "" > gnutls-api.tex
	@echo "" > gnutls-api.texi
	@for i in $(COBJECTS); do \
		echo -n "Creating documentation for file $$i... " && \
		../doc/scripts/gdoc -tex $$i >> gnutls-api.tex && \
		../doc/scripts/gdoc -texinfo $$i >> gnutls-api.texi && \
		echo "ok"; \
	done

dist-hook: gnutls-api.tex gnutls-api.texi
