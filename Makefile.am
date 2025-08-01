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
# along with this file.  If not, see <https://www.gnu.org/licenses/>.

# Note: libdane is required by the abi-check-latest target used in
# distcheck-hook.
AM_DISTCHECK_CONFIGURE_FLAGS = \
	--enable-doc \
	--enable-gtk-doc \
	--enable-libdane \
	--disable-valgrind-tests

SUBDIRS = gl lib extra

if ENABLE_DANE
SUBDIRS += libdane
endif

SUBDIRS += po
if ENABLE_TOOLS
SUBDIRS += src/gl src
else
SUBDIRS += src/gl
endif

if ENABLE_TESTS
SUBDIRS += tests fuzz
endif

if ENABLE_MANPAGES
SUBDIRS += doc/manpages
endif

if ENABLE_DOC
SUBDIRS += doc
endif

ACLOCAL_AMFLAGS = -I m4 -I src/gl/m4 -I lib/unistring/m4 --install

EXTRA_DIST = cfg.mk maint.mk CONTRIBUTING.md README.md COPYING.LESSERv2 COPYING AUTHORS NEWS \
	ChangeLog THANKS INSTALL.md RELEASES.md .mailmap

DISTCLEANFILES = AUTHORS

AUTHORS: Makefile.am .mailmap
	$(AM_V_GEN) { \
		echo -e "The authors list is autogenerated from the git history; sorted by number of commits\n"; \
		git shortlog -sen --no-merges --group author --group trailer:co-authored-by HEAD | cut -f 2 | sed 's/@/ at /g'; \
		echo -e "\n\nThe translators list is autogenerated from po file history\n"; \
		sed -n 's/.*Last-Translator: *\(.*\) *<.*/\1/p' po/*.po | sort -u; \
	} > $@-t && mv $@-t $@

pic-check:
	@echo "Checking for position dependent code"
	readelf -d $(builddir)/lib/.libs/libgnutls.so|grep TEXTREL; if test $$? = 0;then \
	eu-findtextrel $(builddir)/lib/.libs/libgnutls.so; \
	false; \
	fi

ABIDW_COMMON = --drop-private-types --no-show-locs --no-corpus-path
ABIGNORE_FILE = "$(top_srcdir)/devel/libgnutls.abignore"
SYMBOLS_LAST_FILE = "$(top_srcdir)/devel/symbols.last"
LIBGNUTLS_ABI_LAST_FILE = "$(top_srcdir)/devel/abi-dump/libgnutls-latest-$$(uname -m).abi"
LIBDANE_ABI_LAST_FILE = "$(top_srcdir)/devel/abi-dump/libdane-latest-$$(uname -m).abi"

abi-dump-versioned: lib/libgnutls.la libdane/libgnutls-dane.la
	@echo "**************************************************************************"
	@echo "Generating versioned ABI files of current gnutls and gnutls-dane libraries"
	@echo "**************************************************************************"
	@abidw lib/.libs/libgnutls.so $(ABIDW_COMMON) --suppressions $(ABIGNORE_FILE) --out-file "$(srcdir)/devel/abi-dump/libgnutls-$(VERSION)-$$(uname -m).abi"
	@abidw libdane/.libs/libgnutls-dane.so $(ABIDW_COMMON) --out-file "$(srcdir)/devel/abi-dump/libdane-$(VERSION)-$$(uname -m).abi"

abi-dump-latest: lib/libgnutls.la libdane/libgnutls-dane.la
	@echo "****************************************************************"
	@echo "Generating ABI files of current gnutls and gnutls-dane libraries"
	@echo "****************************************************************"
	@abidw lib/.libs/libgnutls.so $(ABIDW_COMMON) --suppressions $(ABIGNORE_FILE) --out-file $(LIBGNUTLS_ABI_LAST_FILE)
	@abidw libdane/.libs/libgnutls-dane.so $(ABIDW_COMMON) --out-file $(LIBDANE_ABI_LAST_FILE)
	@rm -f "./devel/libgnutls-latest-$$(uname -m).tmp"
	@rm -f "./devel/libdane-latest-$$(uname -m).tmp"

abi-check-latest: lib/libgnutls.la libdane/libgnutls-dane.la
	@echo "Checking whether the latest ABI dump matches"
	@abidiff --suppressions $(ABIGNORE_FILE) lib/.libs/libgnutls.so $(LIBGNUTLS_ABI_LAST_FILE) --hd2 "$(srcdir)/lib/includes/gnutls/" --hd2 $(builddir)/lib/includes/gnutls/ ; if test $$? != 0;then \
		echo "*********************************************************"; \
		echo "libgnutls ABI has changed; use 'make files-update'       "; \
		echo "and use 'git diff' to check correctness before committing"; \
		echo "*********************************************************"; \
		false; \
	fi
	@abidiff libdane/.libs/libgnutls-dane.so $(LIBDANE_ABI_LAST_FILE) --hd2 "$(srcdir)/libdane/includes/gnutls/" --hd2 $(builddir)/lib/includes/gnutls/; if test $$? != 0;then \
		echo "*********************************************************"; \
		echo "libgnutls-dane ABI has changed; use 'make files-update'  "; \
		echo "and use 'git diff' to check correctness before committing"; \
		echo "*********************************************************"; \
		false; \
	fi
	@echo "********************************"
	@echo "Current release matches ABI dump"
	@echo "********************************"

ABICHECK_COMMON = --no-added-syms
abi-check: lib/libgnutls.la libdane/libgnutls-dane.la
	@for file in $$(echo $(srcdir)/devel/abi-dump/libgnutls-*-$$(uname -m).abi);do \
		echo "Comparing libgnutls with $$file"; \
		abidiff $${file} lib/.libs/libgnutls.so $(ABICHECK_COMMON) --suppressions $(ABIGNORE_FILE) --hd2 "$(srcdir)/lib/includes/gnutls/" --hd2 $(builddir)/lib/includes/gnutls/; \
		if test $$? != 0;then \
			echo "****************************************************************************"; \
			echo "ABI check failed; If intentional add suppression in devel/libgnutls.abignore"; \
			echo "****************************************************************************"; \
			exit 1; \
		fi; \
	done
	@for file in $$(echo $(srcdir)/devel/abi-dump/libdane-*-$$(uname -m).abi);do \
		echo "Comparing libgnutls-dane with $$file"; \
		abidiff $${file} libdane/.libs/libgnutls-dane.so $(ABICHECK_COMMON) --hd2 "$(srcdir)/libdane/includes/gnutls/" --hd2 $(builddir)/lib/includes/gnutls/; \
		if test $$? != 0;then \
			echo "**********************************************"; \
			echo "ABI check failed; If intentional add a        "; \
			echo "libabigail suppression file for libgnutls-dane"; \
			echo "**********************************************"; \
			exit 1; \
		fi; \
	done
	@echo "********************"
	@echo "ABI checks completed"
	@echo "********************"

symbol-check: lib/libgnutls.la
	@objdump -T $(builddir)/lib/.libs/libgnutls.so | grep -v ' \*UND\*'  | awk '{print $$7 "@" $$6;}' | grep -v GNUTLS_FIPS140 | grep -v GNUTLS_PRIVATE | grep -v '^@' |  sort -u >symbols.last.tmp
	@diff -u $(SYMBOLS_LAST_FILE) symbols.last.tmp >/dev/null 2>&1; if test $$? != 0;then \
		diff -u $(SYMBOLS_LAST_FILE) symbols.last.tmp | grep -v '\-\-\-' >symbols.diff.tmp 2>&1; \
		if grep -e '^-' symbols.diff.tmp;then \
			echo "*******************************************"; \
			echo "Symbols were removed from the library.     "; \
			echo "Check symbols.diff.tmp for more information"; \
			echo "*******************************************"; \
			false; \
		else \
			echo "*************************************************************"; \
			echo "Symbols were added in the library; use 'make files-update'   "; \
			echo "and use 'git diff' to check correctness before committing    "; \
			echo "*************************************************************"; \
			false; \
		fi \
	else \
		test -f symbols.diff.tmp && cat symbols.diff.tmp; \
		echo "**************************"; \
		echo "No symbol changes detected"; \
		echo "**************************"; \
	fi
	rm -f symbols.last.tmp symbols.diff.tmp

include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean

local-code-coverage-output: code-coverage-capture
	cat GnuTLS-$(VERSION)-coverage/index.html|grep headerCovTableEntry|grep '%'|head -1|sed 's/^.*>\([0-9]\+\.[0-9]\+\s*%\)<.*$$/ coverage lines: \1/' || true

files-update:
	$(MAKE) -C doc/ compare-makefile || mv doc/tmp-compare-makefile $(srcdir)/doc/Makefile.am
	$(MAKE) -C doc/manpages compare-makefile || mv doc/manpages/tmp-compare-makefile $(srcdir)/doc/manpages/Makefile.am
	$(MAKE) -C . symbol-check || mv symbols.last.tmp $(SYMBOLS_LAST_FILE)
	@echo "******************************************************************************************"
	@echo "updated auto-generated files; please use git diff to verify the correctness of the changes"
	@echo "******************************************************************************************"

dist-hook:
	if test -d "$(top_srcdir)/devel";then \
		$(MAKE) -C $(top_srcdir) symbol-check && \
		$(MAKE) -C $(top_srcdir) abi-check-latest; \
	fi
	$(MAKE) -C doc/ compare-makefile
	$(MAKE) -C doc/ compare-exported
	$(MAKE) -C doc/manpages compare-makefile
	$(MAKE) ChangeLog
	mv ChangeLog $(distdir)
	touch -c $(distdir)/doc/*.html $(distdir)/doc/*.pdf $(distdir)/doc/*.info

distcheck-hook:
	@test -d "$(top_srcdir)/po/.reference" || { echo "PO files are not downloaded; run ./bootstrap without --skip-po"; exit 1; }

.PHONY: abi-check abi-dump-versioned abi-dump-latest pic-check symbol-check local-code-coverage-output files-update AUTHORS

include $(top_srcdir)/cligen/cligen.mk
noinst_PYTHON = $(cligen_sources)
