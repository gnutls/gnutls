EXTRA_DIST = gnutls.tex gnutls.ps gnutls.html  \
	ex1.tex ex2.tex ex3.tex srp1.tex serv1.tex gnutls.css \
	nx_grp_g.png  prev_g.png  up_g.png fdl.tex macros.tex \
	cover.tex.in

all-local: gnutls.html gnutls.ps 

TEX_OBJECTS = gnutls.tex ../../lib/gnutls-api.tex serv1.tex ex1.tex ex2.tex ex3.tex fdl.tex \
	macros.tex cover.tex

gnutls.ps: $(TEX_OBJECTS)
	-$(LN_S) ../../lib/gnutls-api.tex .
	-latex gnutls.tex && latex gnutls.tex && dvips gnutls.dvi -o gnutls.ps

gnutls.html: $(TEX_OBJECTS)
	-latex2html gnutls.tex -no_subdir 1 -split 0 -local_icons -prefix ./ \
	-info "" 


clean:
	@-rm *.log *.aux *.toc
	@-rm *.pl index.html gnutls.dvi
	@-rm WARNINGS gnutls-api.tex
	