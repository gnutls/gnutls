## Process this file with automake to produce Makefile.in
# Copyright (C) 2006 Free Software Foundation
#
# Author: Simon Josefsson
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

EXTRA_DIST = client.p12 noclient.p12 unclient.p12

dist_check_SCRIPTS = pkcs12

TESTS = pkcs12 pkcs12_s2k

check_PROGRAMS = pkcs12_s2k

AM_CPPFLAGS = -I$(top_srcdir)/lgl -I$(top_builddir)/lgl -I..		\
	-I$(top_srcdir)/gl -I$(top_builddir)/gl				\
	-I$(top_srcdir)/includes -I$(top_builddir)/includes		\
	-I$(top_srcdir)/lib 						\
	-I$(top_srcdir)/doc/examples
AM_LDFLAGS = -no-install
LDADD = ../../lib/libgnutls.la ../../gl/libgnu.la ../../lgl/liblgnu.la ../libutils.la

