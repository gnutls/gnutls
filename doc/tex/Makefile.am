EXTRA_DIST = gnutls.tex gnutls.ps gnutls.html  \
	ex1.tex ex2.tex ex3.tex srp1.tex serv1.tex gnutls.css \
	nx_grp_g.png  prev_g.png  up_g.png fdl.tex macros.tex \
	cover.tex.in img1.png  img3.png  img5.png img2.png img4.png \
	img6.png gnutls-logo.ps

TEX_OBJECTS = gnutls.tex ../../lib/gnutls-api.tex serv1.tex ex1.tex ex2.tex ex3.tex fdl.tex \
	macros.tex cover.tex ciphersuites.tex resumedb.tex translayer.tex asn1.tex ../../lib/asn1-api.tex \
	auth.tex ciphers.tex errors.tex

gnutls.ps: $(TEX_OBJECTS)
	-$(LN_S) ../../lib/gnutls-api.tex .
	-$(LN_S) ../../lib/asn1-api.tex .
	-latex gnutls.tex && latex gnutls.tex && dvips gnutls.dvi -o gnutls.ps

gnutls.html: $(TEX_OBJECTS)
	-latex2html gnutls.tex -no_navigation -no_subdir 1 -split 0 -local_icons -html_version 3.2,math \
	-info "" -white


clean:
	@-rm *.log *.aux *.toc
	@-rm *.pl index.html gnutls.dvi
	@-rm WARNINGS gnutls-api.tex
	