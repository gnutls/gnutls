## Process this file with automake to produce Makefile.in

EXTRA_DIST = ChangeLog NEWS INSTALL README THANKS COPYING COPYING.LIB
SUBDIRS = gl includes lib libextra src doc tests

ACLOCAL_AMFLAGS = -I m4 -I gl/m4

ChangeLog:
	cvs2cl --utc -U .cvsusers --fsf -t -S -I ChangeLog -I .cvs

tag = $(PACKAGE)-`echo $(VERSION) | sed 's/\./_/g'`
htmldir = ../www-$(PACKAGE)

release:
	cvs rtag gnutls_1_1_15 gnutls
	rm -f ChangeLog
	make ChangeLog
	cvs commit -m "" ChangeLog
	cvs rtag -F gnutls_1_1_15 gnutls
	make dist
	gpg -b $(distdir).tar.gz
	gpg --verify $(distdir).tar.gz.sig
	scp $(distdir).tar.gz{,.sig} igloo.linux.gr:/ftp/pub/gnutls/devel
	ssh igloo.linux.gr 'cd /ftp/pub/gnutls/devel && md5sum *.tar.gz *.tar.bz2 > CHECKSUMS'
	cd doc && ./gendocs.sh -o ../$(htmldir)/manual/ $(PACKAGE) "GNU TLS"
	cp -v $(distdir).tar.gz{,.sig} $(htmldir)/releases/
	cd $(htmldir) && cvs add -kb releases/$(distdir).tar.gz{,.sig} && \
		cvs commit -m "Update." manual/ releases/
