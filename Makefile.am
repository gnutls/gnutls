## Process this file with automake to produce Makefile.in

EXTRA_DIST = ChangeLog NEWS INSTALL README THANKS COPYING PGPKEYS COPYING.LIB
SUBDIRS = $(LIBASN1_DIR) includes lib libextra src doc tests

ChangeLog:
	cvs2cl --utc -U .cvsusers --fsf -t -S --prune
