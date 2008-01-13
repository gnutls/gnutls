## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007 Free Software Foundation
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GNUTLS-EXTRA.
#
# GNUTLS-EXTRA is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# GNUTLS-EXTRA is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNUTLS-EXTRA; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

AM_CPPFLAGS = -I$(top_srcdir)/lgl -I$(top_builddir)/lgl	\
	-I$(top_srcdir)/crypto -I$(top_srcdir)/lib	\
	-I$(top_srcdir)/includes -I../../includes	\
	-I$(top_srcdir)/lib/opencdk

if ENABLE_MINITASN1
AM_CPPFLAGS += -I$(top_srcdir)/lib/minitasn1
else
AM_CPPFLAGS += $(LIBTASN1_CFLAGS)
endif

noinst_LTLIBRARIES = libgnutls_openpgp.la

COBJECTS = pgp.c pgpverify.c extras.c compat.c privkey.c output.c

libgnutls_openpgp_la_SOURCES = $(COBJECTS) openpgp.h gnutls_openpgp.h

EXTRA_DIST = pgp-api.texi

pgp-api.texi: $(COBJECTS)
	@echo "" > pgp-api.texi
	@for i in ../gnutls_openpgp.c $(COBJECTS); do \
		echo -n "Creating documentation for file $$i... " && \
		$(top_srcdir)/doc/scripts/gdoc -texinfo $$i >> pgp-api.texi && \
		echo "ok"; \
	done

dist-hook: pgp-api.texi
