INCLUDES = -I$(top_srcdir)/crypto -I$(top_srcdir)/gl -I$(top_srcdir)/libextra -I$(top_srcdir)/lib/minitasn1 -I$(top_srcdir)/libextra/openpgp/ -I$(top_srcdir)/libextra/opencdk -I$(top_srcdir)/lib -I$(top_srcdir)/includes $(LIBOPENCDK_CFLAGS) $(LIBTASN1_CFLAGS) $(LIBGCRYPT_CFLAGS)

noinst_LTLIBRARIES = libgnutls_x509.la

libgnutls_x509_la_SOURCES = crl.c dn.c common.c x509.c extensions.c	\
	dsa.c rfc2818_hostname.c verify.c mpi.c privkey.c pkcs7.c	\
	crq.c xml.c sign.c privkey_pkcs8.c pkcs12.c pkcs12_bag.c	\
	pkcs12_encr.c x509_write.c crl_write.c compat.c dn.h common.h	\
	x509.h extensions.h pkcs7.h compat.h verify.h mpi.h crq.h	\
	sign.h privkey.h pkcs12.h rfc2818.h dsa.h

EXTRA_DIST = x509-api.texi

x509-api.texi: $(COBJECTS)
	@echo "" > x509-api.texi
	@for i in $(COBJECTS); do \
		echo -n "Creating documentation for file $$i... " && \
		../../doc/scripts/gdoc -texinfo $$i >> x509-api.texi && \
		echo "ok"; \
	done

dist-hook: x509-api.texi
