## Process this file with automake to produce Makefile.in

EXTRA_DIST = ChangeLog NEWS INSTALL README THANKS COPYING PGPKEYS
SUBDIRS = lib libextra src doc

ChangeLog:
	cvs2cl --utc -U .cvsusers --fsf -t -S --prune
