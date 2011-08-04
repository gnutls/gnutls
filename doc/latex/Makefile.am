TEX_OBJECTS = gnutls.tex macros.tex fdl.tex cover.tex gnutls.bib

GEN_TEX_OBJECTS = cha-preface.tex cha-library.tex cha-intro-tls.tex cha-auth.tex \
  cha-cert-auth.tex cha-gtls-app.tex cha-tls-app.tex cha-programs.tex cha-support.tex \
  cha-functions.tex error_codes.tex cha-ciphersuites.tex algorithms.tex \
  cha-errors.tex alerts.tex cha-internals.tex

cha-preface.tex: ../cha-preface.texi
	../scripts/mytexi2latex $< > $@

cha-library.tex: ../cha-library.texi
	../scripts/mytexi2latex $< > $@

cha-intro-tls.tex: ../cha-intro-tls.texi
	../scripts/mytexi2latex $< > $@

cha-auth.tex: ../cha-auth.texi
	../scripts/mytexi2latex $< > $@

cha-cert-auth.tex: ../cha-cert-auth.texi
	../scripts/mytexi2latex $< > $@

cha-gtls-app.tex: ../cha-gtls-app.texi
	../scripts/mytexi2latex $< > $@

cha-tls-app.tex: ../cha-tls-app.texi
	../scripts/mytexi2latex $< > $@

cha-programs.tex: ../cha-programs.texi
	../scripts/mytexi2latex $< > $@

cha-support.tex: ../cha-support.texi
	../scripts/mytexi2latex $< > $@

cha-functions.tex: ../cha-functions.texi
	../scripts/mytexi2latex $< > $@

cha-internals.tex: ../cha-internals.texi
	../scripts/mytexi2latex $< > $@

cha-errors.tex: ../cha-errors.texi
	../scripts/mytexi2latex $< > $@

cha-ciphersuites.tex: ../cha-ciphersuites.texi
	../scripts/mytexi2latex $< > $@

error_codes.tex: $(top_srcdir)/lib/gnutls_errors.c $(srcdir)/../errcodes
	$(builddir)/../errcodes --latex > $@-tmp
	mv -f $@-tmp $@

algorithms.tex: ../printlist
	$(builddir)/../printlist --latex > $@-tmp
	mv -f $@-tmp $@

alerts.tex: ../alert-printlist
	$(builddir)/../alert-printlist --latex > $@-tmp
	mv -f $@-tmp $@

gnutls-api.tex: $(srcdir)/../../lib/*.c $(srcdir)/../../lib/ext/*.c $(srcdir)/../../lib/auth/*.c $(srcdir)/../../lib/algorithms/*.c
	echo "" > $@-tmp
	for i in $^; do \
		echo -n "Creating documentation for file $$i... " && \
		$(srcdir)/../scripts/gdoc -tex $$i >> $@-tmp && \
		echo "ok"; \
	done
	$(srcdir)/../scripts/sort1.pl < $@-tmp > $@-tmp2
	$(srcdir)/../scripts/split.pl functions < $@-tmp 
	rm -f $@-tmp
	mv -f $@-tmp2 $@

x509-api.tex: $(srcdir)/../../lib/x509/*.c
	echo "" > $@-tmp
	for i in $^; do \
		echo -n "Creating documentation for file $$i... " && \
		$(srcdir)/../scripts/gdoc -tex $$i >> $@-tmp && \
		echo "ok"; \
	done
	$(srcdir)/../scripts/sort1.pl < $@-tmp > $@-tmp2
	$(srcdir)/../scripts/split.pl functions < $@-tmp 
	rm -f $@-tmp
	mv -f $@-tmp2 $@

pgp-api.tex: $(srcdir)/../../lib/openpgp/*.c
	echo "" > $@-tmp
	for i in $^; do \
		echo -n "Creating documentation for file $$i... " && \
		$(srcdir)/../scripts/gdoc -tex $$i >> $@-tmp && \
		echo "ok"; \
	done
	$(srcdir)/../scripts/sort1.pl < $@-tmp > $@-tmp2
	$(srcdir)/../scripts/split.pl functions < $@-tmp 
	rm -f $@-tmp
	mv -f $@-tmp2 $@

extra-api.tex: $(srcdir)/../../libextra/gnutls_extra.c
	echo "" > $@-tmp
	for i in $^; do \
		echo -n "Creating documentation for file $$i... " && \
		$(srcdir)/../scripts/gdoc -tex $$i >> $@-tmp && \
		echo "ok"; \
	done
	$(srcdir)/../scripts/sort1.pl < $@-tmp > $@-tmp2
	$(srcdir)/../scripts/split.pl functions < $@-tmp 
	rm -f $@-tmp
	mv -f $@-tmp2 $@

SOURCE_GEN_FILES =  extra-api.tex pgp-api.tex x509-api.tex gnutls-api.tex

gnutls.pdf: $(TEX_OBJECTS) $(GEN_TEX_OBJECTS) $(SOURCE_GEN_FILES)
	-pdflatex gnutls.tex
	-bibtex gnutls
	-makeindex gnutls.idx
	-pdflatex gnutls.tex && pdflatex gnutls.tex

clean-am:
	rm -f $(GEN_TEX_OBJECTS) $(SOURCE_GEN_FILES) gnutls.aux gnutls.bbl gnutls.blg gnutls.idx gnutls.ilg gnutls.ind gnutls.log gnutls.out gnutls.toc
	rm -rf functions

