# source files added here must be added to ../Makefile.am
# to be compiled.

COBJECTS = crl.c dn.c common.c x509.c extensions.c dsa.c \
	rfc2818_hostname.c verify.c mpi.c privkey.c pkcs7.c \
	crq.c xml.c sign.c pkcs5.c privkey_pkcs8.c pkcs12.c \
	pkcs12_bag.c pkcs12_encr.c x509_write.c crl_write.c compat.c

EXTRA_DIST = dn.h common.h x509.h extensions.h pkcs7.h \
	compat.h verify.h mpi.h crq.h sign.h pkcs5.h \
	privkey.h pkcs12.h rfc2818.h dsa.h $(COBJECTS) \
	x509-api.tex x509-api.texi

x509-api.tex x509-api.texi: $(COBJECTS)
	@echo "" > x509-api.tex
	@echo "" > x509-api.texi
	@for i in $(COBJECTS); do \
		echo -n "Creating documentation for file $$i... " && \
		../../doc/scripts/gdoc -tex $$i >> x509-api.tex && \
		../../doc/scripts/gdoc -texinfo $$i >> x509-api.texi && \
		echo "ok"; \
	done

dist-hook: x509-api.tex x509-api.texi
