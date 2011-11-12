# Copyright (C) 2006-2011 Free Software Foundation, Inc.
#
# Author: Simon Josefsson
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

WFLAGS ?= --enable-gcc-warnings
ADDFLAGS ?=
CFGFLAGS ?= --enable-gtk-doc --enable-gtk-doc-pdf $(ADDFLAGS) $(WFLAGS)
PACKAGE ?= gnutls

INDENT_SOURCES = `find . -name \*.[ch] -o -name gnutls.h.in | grep -v -e ^./build-aux/ -e ^./lib/minitasn1/ -e ^./lib/build-aux/ -e ^./gl/ -e ^./src/cfg/ -e -gaa.[ch] -e asn1_tab.c -e ^./tests/suite/`

ifeq ($(.DEFAULT_GOAL),abort-due-to-no-makefile)
.DEFAULT_GOAL := bootstrap
endif

PODIR := po
PO_DOMAIN := libgnutls

local-checks-to-skip = sc_GPL_version sc_bindtextdomain			\
	sc_immutable_NEWS sc_program_name sc_prohibit_atoi_atof		\
	sc_prohibit_empty_lines_at_EOF sc_prohibit_hash_without_use	\
	sc_prohibit_have_config_h sc_prohibit_magic_number_exit		\
	sc_prohibit_strcmp sc_require_config_h				\
	sc_require_config_h_first sc_texinfo_acronym sc_trailing_blank	\
	sc_unmarked_diagnostics sc_useless_cpp_parens

VC_LIST_ALWAYS_EXCLUDE_REGEX = ^maint.mk|(build-aux/|gl/|src/cfg/|tests/suite/ecore/|doc/protocol/).*$$

# Explicit syntax-check exceptions.
exclude_file_name_regexp--sc_cast_of_alloca_return_value = ^guile/modules/gnutls/build/priorities.scm|guile/src/core.c$$
exclude_file_name_regexp--sc_error_message_period = ^src/crywrap/crywrap.c$$
exclude_file_name_regexp--sc_error_message_uppercase = ^doc/examples/ex-cxx.cpp|guile/src/core.c|src/certtool.c|src/crywrap/crywrap.c|tests/pkcs12_encode.c$$
exclude_file_name_regexp--sc_file_system = ^doc/doxygen/Doxyfile
exclude_file_name_regexp--sc_prohibit_cvs_keyword = ^lib/nettle/.*$$
exclude_file_name_regexp--sc_prohibit_undesirable_word_seq = ^tests/nist-pkits/gnutls-nist-tests.html$$
exclude_file_name_regexp--sc_space_tab = ^gtk-doc.make|doc/.*.(pdf|png)|tests/nist-pkits/|tests/suite/x509paths/.*$$
exclude_file_name_regexp--sc_two_space_separator_in_usage = ^doc/cha-programs.texi|tests/sha2/sha2|tests/sha2/sha2-dsa$$

autoreconf:
	for f in $(PODIR)/*.po.in; do \
		cp $$f `echo $$f | sed 's/.in//'`; \
	done
	mv build-aux/config.rpath build-aux/config.rpath-
	autopoint
	rm -f m4/codeset.m4 m4/gettext.m4 m4/glibc21.m4 m4/glibc2.m4 m4/iconv.m4 m4/intdiv0.m4 m4/intldir.m4 m4/intl.m4 m4/intlmacosx.m4 m4/intmax.m4 m4/inttypes_h.m4 m4/inttypes-pri.m4 m4/lcmessage.m4 m4/lib-ld.m4 m4/lib-link.m4 m4/lib-prefix.m4 m4/lock.m4 m4/longlong.m4 m4/nls.m4 m4/po.m4 m4/printf-posix.m4 m4/progtest.m4 m4/size_max.m4 m4/stdint_h.m4 m4/uintmax_t.m4 m4/wchar_t.m4 m4/wint_t.m4 m4/visibility.m4 m4/xsize.m4
	test -f ./configure || AUTOPOINT=true autoreconf --install
	mv build-aux/config.rpath- build-aux/config.rpath

update-po: refresh-po
	for f in `ls $(PODIR)/*.po | grep -v quot.po`; do \
		cp $$f $$f.in; \
	done
	git add $(PODIR)/*.po.in
	git commit -m "Sync with TP." $(PODIR)/LINGUAS $(PODIR)/*.po.in

bootstrap: autoreconf
	./configure $(CFGFLAGS)

# The only non-lgpl modules used are: gettime progname timespec. Those
# are not used (and must not be used) in the library)
glimport:
	gnulib-tool --add-import

# Code Coverage

pre-coverage:
	./configure --disable-cxx
	ln -s . gl/tests/glthread/glthread
	ln -sf /usr/local/share/gaa/gaa.skel src/gaa.skel

web-coverage:
	rm -fv `find $(htmldir)/coverage -type f | grep -v CVS`
	cp -rv doc/coverage/* $(htmldir)/coverage/

upload-web-coverage:
	cd $(htmldir) && \
		cvs commit -m "Update." coverage

# Release

ChangeLog:
	git log --pretty --numstat --summary --since="2009 November 07" -- | git2cl > ChangeLog
	cat .clcopying >> ChangeLog

tag = $(PACKAGE)_`echo $(VERSION) | sed 's/\./_/g'`
htmldir = ../www-$(PACKAGE)

release: syntax-check prepare upload web upload-web

prepare:
	! git tag -l $(tag) | grep $(PACKAGE) > /dev/null
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck
	git commit -m Generated. ChangeLog
	git tag -u b565716f! -m $(VERSION) $(tag)

upload:
	git push
	git push --tags
	build-aux/gnupload --to alpha.gnu.org:$(PACKAGE) $(distdir).tar.bz2
	scp $(distdir).tar.bz2 $(distdir).tar.bz2.sig igloo.linux.gr:~ftp/pub/gnutls/devel/
	ssh igloo.linux.gr 'cd ~ftp/pub/gnutls/devel/ && sha1sum *.tar.bz2 > CHECKSUMS'
	cp $(distdir).tar.bz2 $(distdir).tar.bz2.sig ../releases/$(PACKAGE)/

web:
	echo generating documentation for $(PACKAGE)
	cd doc && $(SHELL) ../build-aux/gendocs.sh \
		--html "--css-include=texinfo.css" \
		-o ../$(htmldir)/manual/ $(PACKAGE) "$(PACKAGE_NAME)"
	#cd doc/doxygen && doxygen && cd ../.. && cp -v doc/doxygen/html/* $(htmldir)/devel/doxygen/ && cd doc/doxygen/latex && make refman.pdf && cd ../../../ && cp doc/doxygen/latex/refman.pdf $(htmldir)/devel/doxygen/$(PACKAGE).pdf
	cp -v doc/reference/html/*.html doc/reference/html/*.png doc/reference/html/*.devhelp doc/reference/html/*.css $(htmldir)/reference/
	#cp -v doc/cyclo/cyclo-$(PACKAGE).html $(htmldir)/cyclo/

upload-web:
	cd $(htmldir) && \
		cvs commit -m "Update." manual/ reference/ \
			doxygen/ devel/ cyclo/
