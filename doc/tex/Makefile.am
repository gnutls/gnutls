EXTRA_DIST = gnutls-api.tex gnutls.tex gnutls.ps gnutls.html ASN1.readme.txt \
	ex1.tex ex2.tex ex3.tex srp1.tex serv1.tex gnutls.css \
	nx_grp_g.png  prev_g.png  up_g.png

gnutls-api: gnutls.html gnutls.ps
gnutls-api.tex: 
	@echo "\\newpage" > gnutls-api.tex
	@echo "\\section{Function Reference}" >> gnutls-api.tex
	@../scripts/gdoc -tex ../../lib/*.c >> gnutls-api.tex

gnutls.ps: gnutls.tex gnutls-api.tex
	-latex gnutls.tex && latex gnutls.tex && dvips gnutls.dvi -o gnutls.ps

gnutls.html: gnutls.tex gnutls-api.tex
	-latex2html gnutls.tex -no_subdir 1 -split 0 -local_icons
