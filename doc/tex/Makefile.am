EXTRA_DIST = gnutls.tex gnutls.ps \
	ex1.tex ex2.tex ex3.tex srp1.tex serv1.tex ex4.tex \
	fdl.tex cover.tex.in gnutls-logo.ps layers.eps pgp-fig1.eps \
	x509-1.eps internals.eps

TEX_OBJECTS = gnutls.tex ../../lib/gnutls-api.tex serv1.tex ex1.tex ex2.tex ex3.tex fdl.tex \
	macros.tex cover.tex ciphersuites.tex handshake.tex translayer.tex \
	auth.tex ciphers.tex errors.tex layers.tex alert.tex record.tex \
	funcs.tex examples.tex ex4.tex ../../libextra/gnutls-extra-api.tex \
	memory.tex openpgp.tex x509.tex howto.tex openssl.tex \
	ex-rfc2818.tex appendix.tex x509cert.xml.tex pgpcert.xml.tex \
	serv-export.tex serv-srp.tex programs.tex library.tex certificate.tex \
	tlsintro.tex ex-alert.tex compression.tex

gnutls.html: $(TEX_OBJECTS)            
	-latex2html gnutls.tex -no_navigation -split 0 \
	-local_icons -html_version 3.2,math -info "" -white

gnutls.ps: $(TEX_OBJECTS)
	-$(LN_S) ../../lib/gnutls-api.tex .
	-$(LN_S) ../../libextra/gnutls-extra-api.tex .
	-latex gnutls.tex
	-makeindex gnutls.idx
	-latex gnutls.tex && latex gnutls.tex && dvips gnutls.dvi -o gnutls.ps

clean:
	@-rm *.log *.aux *.toc *.png *.old *.html *.css *~
	@-rm *.pl gnutls.dvi
	@-rm WARNINGS gnutls-api.tex gnutls-extra-api.tex
