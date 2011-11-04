TEX_OBJECTS = gnutls.tex macros.tex macros-epub.tex fdl.tex cover.tex gnutls.bib \
	cover-epub.tex

GEN_TEX_OBJECTS = cha-preface.tex cha-library.tex cha-intro-tls.tex cha-auth.tex \
  cha-cert-auth.tex cha-gtls-app.tex sec-tls-app.tex cha-programs.tex cha-support.tex \
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

sec-tls-app.tex: ../sec-tls-app.texi
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

error_codes.tex: $(top_srcdir)/lib/gnutls_errors.c
	$(MAKE) -C .. errcodes printlist alert-printlist
	$(builddir)/../errcodes --latex > $@-tmp
	mv -f $@-tmp $@

algorithms.tex:
	$(MAKE) -C .. errcodes printlist alert-printlist
	$(builddir)/../printlist --latex > $@-tmp
	mv -f $@-tmp $@

alerts.tex:
	$(MAKE) -C .. errcodes printlist alert-printlist
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

gnutls-enums.tex: $(srcdir)/../../lib/includes/gnutls/*.h
	echo "" > $@-tmp
	for i in $^; do \
		echo -n "Creating documentation for file $$i... " && \
		$(srcdir)/../scripts/gdoc -tex $$i >> $@-tmp && \
		echo "ok"; \
	done
	$(srcdir)/../scripts/split.pl enums enum < $@-tmp
	mv -f $@-tmp $@

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

SOURCE_GEN_FILES =  pgp-api.tex x509-api.tex gnutls-api.tex gnutls-enums.tex

PDF_FILES = gnutls-client-server-use-case.pdf gnutls-crypto-layers.pdf \
	gnutls-handshake-sequence.pdf gnutls-handshake-state.pdf \
	gnutls-internals.pdf gnutls-layers.pdf gnutls-logo.pdf \
	gnutls-modauth.pdf gnutls-pgp.pdf gnutls-x509.pdf pkcs11-vision.pdf

gnutls.pdf: $(SOURCE_GEN_FILES) $(TEX_OBJECTS) $(GEN_TEX_OBJECTS)
	$(MAKE) -C .. errcodes printlist alert-printlist
#	for i in $(PDF_FILES);do cp ../$$i .;done
	pdflatex gnutls.tex
	bibtex gnutls
	makeindex gnutls.idx
	pdflatex gnutls.tex && pdflatex gnutls.tex
#	for i in $(PDF_FILES);do rm -f $$i;done

PNG_FILES = gnutls-client-server-use-case.png gnutls-crypto-layers.png \
	gnutls-handshake-sequence.png gnutls-handshake-state.png \
	gnutls-internals.png gnutls-layers.png gnutls-logo.png \
	gnutls-modauth.png gnutls-pgp.png gnutls-x509.png pkcs11-vision.png

epub.html: $(SOURCE_GEN_FILES) $(TEX_OBJECTS) $(GEN_TEX_OBJECTS)
	$(MAKE) -C .. errcodes printlist alert-printlist
	mkdir -p epub
	for i in $(PNG_FILES);do cp ../$$i epub;done
	htlatex epub.tex "xhtml,pmathml" " -cunihtf -utf8 -cvalidate'"
	bibtex epub
	makeindex epub.idx
	htlatex epub.tex "xhtml,pmathml" " -cunihtf -utf8 -cvalidate'"
	cp epub*.html epub
	sed -i 's/\.\.\//\.\//g' epub/epub.html
	cd epub && zip gnutls-epub.zip *
#	for i in $(PNG_FILES);do rm -f $$i;done

clean-am:
	rm -f $(GEN_TEX_OBJECTS) $(SOURCE_GEN_FILES) gnutls.aux gnutls.bbl gnutls.blg gnutls.idx \
	gnutls.ilg gnutls.ind gnutls.log gnutls.out gnutls.toc epub.4ct epub.4tc epub.aux epub.bbl \
	epub.blg epub.css epub.dvi epub*.html epub.idv epub.idx epub.ilg epub.ind epub.lg epub.lof \
	epub.log epub.lot epub.out epub.xref epub.toc epub.tmp
	rm -rf functions enums epub $(PNG_FILES) $(PDF_FILES)
