EXTRA_DIST = gnutls.tex gnutls.ps \
	fdl.tex cover.tex.in gnutls-logo.ps layers.eps pgp-fig1.eps \
	x509-1.eps internals.eps gnutls.bib $(TEX_OBJECTS)

# If you add any examples here, also change the ../examples/Makefile.am
# to include the C source.
EXAMPLE_OBJECTS = ex-alert.tex ex-client-srp.tex ex-serv-export.tex \
	ex-client2.tex ex-x509-info.tex ex-rfc2818.tex \
	ex-serv1.tex ex-client-resume.tex ex-serv-srp.tex \
	ex-serv-pgp.tex ex-pgp-keyserver.tex ex-cert-select.tex \
	ex-crq.tex ex-session-info.tex ex-pkcs12.tex

TEX_OBJECTS = gnutls.tex ../../lib/gnutls-api.tex fdl.tex ../../lib/x509/x509-api.tex \
	../../libextra/openpgp/pgp-api.tex \
	macros.tex cover.tex ciphersuites.tex handshake.tex translayer.tex \
	auth.tex ciphers.tex errors.tex layers.tex alert.tex record.tex \
	funcs.tex examples.tex ../../libextra/gnutls-extra-api.tex \
	memory.tex cert_auth.tex howto.tex openssl.tex \
	appendix.tex x509cert.xml.tex pgpcert.xml.tex \
	programs.tex library.tex certificate.tex record_weaknesses.tex \
	tlsintro.tex compression.tex $(EXAMPLE_OBJECTS) preface.tex \
	tls_extensions.tex srp.tex preparation.tex callbacks.tex \
	supported_ciphersuites.tex

gnutls.html: build_api_pgp build_api_lib build_api_x509 build_api_extra $(TEX_OBJECTS)
	-latex2html gnutls.tex -no_navigation -split 0 \
	-local_icons -html_version 3.2,math -info "" -white

build_api_lib:
	cd ../../lib && make gnutls-api.tex

build_api_x509:
	cd ../../lib/x509 && make x509-api.tex

build_api_pgp:
	cd ../../libextra/openpgp && make pgp-api.tex

build_api_extra:
	cd ../../libextra && make gnutls-extra-api.tex

error_codes.tex: ../../lib/gnutls_errors_int.h ../../lib/gnutls_errors.c
	-../../src/retcodes > error_codes.tex

gnutls-api.tex: ../../lib/gnutls-api.tex
	-../scripts/sort1.pl < ../../lib/gnutls-api.tex > gnutls-api.tex

gnutls-extra-api.tex: ../../libextra/gnutls-extra-api.tex
	-../scripts/sort1.pl < ../../libextra/gnutls-extra-api.tex > gnutls-extra-api.tex

x509-api.tex: ../../lib/x509/x509-api.tex
	-../scripts/sort1.pl < ../../lib/x509/x509-api.tex > x509-api.tex

pgp-api.tex: ../../libextra/openpgp/pgp-api.tex
	-../scripts/sort1.pl < ../../libextra/openpgp/pgp-api.tex > pgp-api.tex

DOC_OBJECTS = pgp-api.tex x509-api.tex gnutls-api.tex gnutls-extra-api.tex error_codes.tex

gnutls.ps: build_api_lib build_api_x509 build_api_extra $(TEX_OBJECTS) $(DOC_OBJECTS)
	-latex gnutls.tex
	-bibtex gnutls
	-makeindex gnutls.idx
	-latex gnutls.tex && latex gnutls.tex && dvips gnutls.dvi -o gnutls.ps

clean:
	@-rm *.log *.aux *.toc *.png *.old *.html *.css *~
	@-rm *.pl gnutls.dvi
	@-rm WARNINGS gnutls-api.tex gnutls-extra-api.tex error_codes.tex x509-api.tex

examples: $(EXAMPLE_OBJECTS)
	@echo "Generating example programs... "
	@echo "They will be placed in doc/examples/ directory."
	@echo ""
	@for i in $(EXAMPLE_OBJECTS); do \
		out=`echo -n $$i|sed s/\.tex//`; \
		cat $$i|grep -v "^\\\\" > ../examples/$$out.c; \
		done

dist-hook: examples

.PHONY: build_api_lib build_api_x509 build_api_extra
