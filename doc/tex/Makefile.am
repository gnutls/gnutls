EXTRA_DIST = gnutls.tex gnutls.ps \
	fdl.tex cover.tex.in gnutls-logo.ps layers.eps pgp-fig1.eps \
	x509-1.eps internals.eps examples gnutls.bib

# If you add any examples here, also change the ../examples/Makefile.am
# to include the C source.
EXAMPLE_OBJECTS = ex-alert.tex ex-client-srp.tex ex-serv-export.tex \
	ex-client1.tex ex-client2.tex ex-info.tex ex-rfc2818.tex \
	ex-serv1.tex ex-client-resume.tex ex-serv-srp.tex \
	ex-serv-pgp.tex ex-pgp-keyserver.tex

TEX_OBJECTS = gnutls.tex ../../lib/gnutls-api.tex fdl.tex \
	macros.tex cover.tex ciphersuites.tex handshake.tex translayer.tex \
	auth.tex ciphers.tex errors.tex layers.tex alert.tex record.tex \
	funcs.tex examples.tex ../../libextra/gnutls-extra-api.tex \
	memory.tex openpgp.tex x509.tex howto.tex openssl.tex \
	appendix.tex x509cert.xml.tex pgpcert.xml.tex \
	programs.tex library.tex certificate.tex record_weaknesses.tex \
	tlsintro.tex compression.tex $(EXAMPLE_OBJECTS) \
	tls_extensions.tex srp.tex preparation.tex

gnutls.html: $(TEX_OBJECTS)            
	-latex2html gnutls.tex -no_navigation -split 0 \
	-local_icons -html_version 3.2,math -info "" -white

error_codes.tex: ../../lib/gnutls_errors_int.h ../../lib/gnutls_errors.c
	-../../src/retcodes > error_codes.tex

gnutls-api.tex: ../../lib/gnutls-api.tex
	-../scripts/sort1.pl < ../../lib/gnutls-api.tex > gnutls-api.tex

gnutls-extra-api.tex: ../../libextra/gnutls-extra-api.tex
	-../scripts/sort1.pl < ../../libextra/gnutls-extra-api.tex > gnutls-extra-api.tex

DOC_OBJECTS = gnutls-api.tex gnutls-extra-api.tex error_codes.tex

gnutls.ps: $(TEX_OBJECTS) $(DOC_OBJECTS)
	-latex gnutls.tex
	-bibtex gnutls
	-makeindex gnutls.idx
	-latex gnutls.tex && latex gnutls.tex && dvips gnutls.dvi -o gnutls.ps

clean:
	@-rm *.log *.aux *.toc *.png *.old *.html *.css *~
	@-rm *.pl gnutls.dvi
	@-rm WARNINGS gnutls-api.tex gnutls-extra-api.tex error_codes.tex

examples: $(EXAMPLE_OBJECTS)
	@echo "Generating example programs... "
	@echo "They will be placed in doc/examples/ directory."
	@echo ""
	@for i in $(EXAMPLE_OBJECTS); do \
		out=`echo -n $$i|sed s/\.tex//`; \
		cat $$i|grep -v "^\\\\" > ../examples/$$out.c; \
		done

