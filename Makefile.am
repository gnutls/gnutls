## Process this file with automake to produce Makefile.in

EXTRA_DIST = ChangeLog NEWS INSTALL README THANKS COPYING COPYING.LIB
SUBDIRS = includes lib libextra src doc tests

ACLOCAL_AMFLAGS = -I m4

ChangeLog:
	cvs2cl --utc -U .cvsusers --fsf -t -S -I ChangeLog -I .cvs
