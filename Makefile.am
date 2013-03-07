## Process this file with automake to produce Makefile.in
# Copyright (C) 2000-2012 Free Software Foundation, Inc.
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GnuTLS.
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

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc --disable-valgrind-tests

SUBDIRS = gl lib extra

if ENABLE_DANE
SUBDIRS += libdane
endif

SUBDIRS += po src
if ENABLE_DOC
SUBDIRS += doc
endif
if ENABLE_TESTS
SUBDIRS += tests
endif

if HAVE_GUILE
SUBDIRS += guile
endif

ACLOCAL_AMFLAGS = -I m4 -I gl/m4 -I src/libopts/m4

EXTRA_DIST = cfg.mk maint.mk .clcopying

dist-hook: 
	rm -f ChangeLog
	make ChangeLog
	make -C doc/ compare-makefile
	make -C doc/manpages compare-makefile
	cp -f ChangeLog $(distdir)/
	sed 's/\@VERSION\@/$(VERSION)/g' -i $(distdir)/src/args-std.def
	cd $(distdir)/src/ && for i in *.def;do \
		if test x"$$i" = x"args-std.def";then  continue; fi; \
		autogen $$i; \
		cp $$i $$i.tmp; \
		sed -i 's/@subheading \(.*\)/@*\n@var{\1}\n@*/' $$i.tmp; \
		autogen -Tagman-cmd.tpl $$i.tmp; \
		rm -f $$i.tmp; \
		mv -f *.1 ../doc/manpages/; \
	done
	sed 's/\@\@VERSION\@\@/$(VERSION)/g' -i $(distdir)/doc/invoke-*.texi
	touch $(distdir)/doc/*.html $(distdir)/doc/*.pdf
