EXTRA_DIST = gnutls.tex gnutls.ps asn1.ps \
	ex1.tex ex2.tex ex3.tex srp1.tex serv1.tex ex4.tex \
	fdl.tex cover.tex.in gnutls-logo.ps layers.ps

TEX_OBJECTS = gnutls.tex ../../lib/gnutls-api.tex serv1.tex ex1.tex ex2.tex ex3.tex fdl.tex \
	macros.tex cover.tex ciphersuites.tex handshake.tex translayer.tex asn1.tex ../../lib/asn1-api.tex \
	auth.tex ciphers.tex errors.tex layers.tex alert.tex record.tex \
	funcs.tex examples.tex ex4.tex ../../libextra/gnutls-extra-api.tex

ASN1_TEX_OBJECTS = fdl.tex asn1.tex ../../lib/asn1-api.tex

gnutls.ps: $(TEX_OBJECTS)
	-$(LN_S) ../../lib/gnutls-api.tex .
	-$(LN_S) ../../libextra/gnutls-extra-api.tex .
	-$(LN_S) ../../lib/asn1-api.tex .
	-latex gnutls.tex && latex gnutls.tex && dvips gnutls.dvi -o gnutls.ps

asn1.ps: $(ASN1_TEX_OBJECTS)
	-$(LN_S) ../lib/asn1-api.tex .
	-latex asn1.tex && latex asn1.tex && dvips asn1.dvi -o asn1.ps

clean:
	@-rm *.log *.aux *.toc
	@-rm *.pl gnutls.dvi
	@-rm WARNINGS gnutls-api.tex gnutls-extra-api.tex
