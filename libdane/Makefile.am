## Process this file with automake to produce Makefile.in
# Copyright (C) 2012 KU Leuven
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of libdane.
#
# libdane is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# GnuTLS-extra is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

ACLOCAL_AMFLAGS = -I ../m4 -I ../gl/m4

AM_CFLAGS = $(WERROR_CFLAGS) $(WSTACK_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = \
	-I$(srcdir)/../gl			\
	-I$(builddir)/../gl			\
	-I$(builddir)/../lib/includes	\
	-I$(srcdir)/../lib/includes	\
	-I$(srcdir)/includes		\
	-I$(builddir)/includes

SUBDIRS = includes

defexecdir = $(bindir)
defexec_DATA = 


libdane_la_LDFLAGS = -no-undefined

if ENABLE_DANE
lib_LTLIBRARIES = libdane.la

libdane_la_SOURCES = dane.c errors.c libdane.map

libdane_la_LIBADD = ../gl/libgnu.la \
	../lib/libgnutls.la

libdane_la_LDFLAGS += -version-info $(LT_DANE_CURRENT):$(LT_DANE_REVISION):$(LT_DANE_AGE)

libdane_la_LIBADD += $(LIBSOCKET) $(UNBOUND_LIBS)

if HAVE_LD_VERSION_SCRIPT
libdane_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libdane.map
else
libdane_la_LDFLAGS += -export-symbols-regex '^(dane).*'
endif

if HAVE_LD_OUTPUT_DEF
libdane_la_LDFLAGS += \
	-Wl,--output-def,libdane-$(DLL_VERSION).def
libdane-$(DLL_VERSION).def: libdane.la
defexec_DATA += libdane-$(DLL_VERSION).def
endif
endif

DISTCLEANFILES = $(defexec_DATA)
