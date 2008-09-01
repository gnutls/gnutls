## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008 Free Software Foundation
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GNUTLS.
#
# The GNUTLS library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# The GNUTLS library is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with the GNUTLS library; if not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA

AM_CPPFLAGS = -I$(top_srcdir)/lib -I$(top_srcdir)/lgl -I$(top_builddir)/lgl

noinst_LTLIBRARIES = libminitasn1.la

libminitasn1_la_SOURCES = libtasn1.h gstr.h errors.h int.h		\
        parser_aux.h structure.h element.h decoding.c gstr.c errors.c	\
        parser_aux.c structure.c element.c coding.c

EXTRA_DIST = README
