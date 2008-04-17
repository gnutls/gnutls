## Process this file with automake to produce Makefile.in
# Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005,
#               2006, 2007, 2008 Free Software Foundation
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GNUTLS.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc

SUBDIRS = lgl gl includes lib libextra src doc tests po

if HAVE_GUILE
SUBDIRS += guile
endif

ACLOCAL_AMFLAGS = -I m4 -I gl/m4 -I lgl/m4

EXTRA_DIST = cfg.mk .clcopying

# Maintainer targets

ChangeLog:
	git log --pretty --numstat --summary --since="2005 November 07" -- | git2cl > ChangeLog
	cat .clcopying >> ChangeLog

tag = $(PACKAGE)_`echo $(VERSION) | sed 's/\./_/g'`
htmldir = ../www-$(PACKAGE)

release:
	! git-tag -l $(tag) | grep $(PACKAGE) > /dev/null
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck
	cd doc && ../build-aux/gendocs.sh -o ../$(htmldir)/manual/ $(PACKAGE) "GNU TLS"
	git commit -m Generated. ChangeLog
	git-tag -u b565716f! -m $(VERSION) $(tag)
	gpg -b $(distdir).tar.bz2
	gpg --verify $(distdir).tar.bz2.sig
	cp -v $(distdir).tar.bz2 $(distdir).tar.bz2.sig $(htmldir)/releases/
	cp -v doc/reference/html/*.html doc/reference/html/*.png doc/reference/html/*.css doc/reference/html/*.devhelp $(htmldir)/reference/
	git-push --tags
	git-push
	scp $(distdir).tar.bz2 $(distdir).tar.bz2.sig igloo.linux.gr:~ftp/pub/gnutls/devel/
	ssh igloo.linux.gr 'cd ~ftp/pub/gnutls/devel/ && sha1sum *.tar.bz2 > CHECKSUMS'
	build-aux/gnupload --to alpha.gnu.org:gnutls $(distdir).tar.bz2
	cd $(htmldir) && \
		cvs add -kb releases/$(distdir).tar.bz2 \
			releases/$(distdir).tar.bz2.sig && \
		cvs commit -m "Update." manual/ reference/ releases/
