## Process this file with automake to produce Makefile.in

nobase_include_HEADERS = gnutls/extra.h gnutls/gnutls.h $(OPENSSL_H) \
	gnutls/compat4.h gnutls/x509.h gnutls/compat8.h gnutls/pkcs12.h \
	gnutls/openpgp.h

if ENABLE_OPENSSL
OPENSSL_H = gnutls/openssl.h
else
OPENSSL_H = 
endif

SUBDIRS = gnutls

