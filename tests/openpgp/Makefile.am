## Process this file with automake to produce Makefile.in
# Copyright (C) 2007 Free Software Foundation
#
# Author: Ludovic Courtès.
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

openpgp_sources = keyring.c

if ENABLE_OPENPGP
TESTS_ENVIRONMENT = $(VALGRIND)

TESTS = keyring

check_PROGRAMS = keyring

AM_CPPFLAGS = -I$(top_srcdir)/includes -I$(top_builddir)/includes	\
	      -I$(top_srcdir)/tests
LDADD = -L$(top_builddir)/libextra -lgnutls-extra	\
        -L$(top_builddir)/lib      -lgnutls		\
	-L$(top_builddir)/tests    -lutils

else

EXTRA_DIST = $(openpgp_sources)

endif

