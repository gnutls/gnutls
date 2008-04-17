## Process this file with automake to produce Makefile.in
# Copyright (C) 2005, 2006, 2007, 2008 Free Software Foundation
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

AM_CPPFLAGS = -I$(top_srcdir)/includes -I$(top_builddir)/includes \
		-I$(top_srcdir)/lgl -I$(top_builddir)/lgl \
		-I$(top_srcdir)/gl -I$(top_builddir)/gl
AM_LDFLAGS = -no-install
LDADD = libexamples.la \
	../../lib/libgnutls.la	\
	../../libextra/libgnutls-extra.la \
	../../gl/libgnu.la

noinst_PROGRAMS = ex-cert-select ex-client2 ex-client-resume	\
	ex-crq ex-serv1 ex-serv-export

if ENABLE_ANON
noinst_PROGRAMS += ex-client1 ex-serv-anon
noinst_PROGRAMS += ex-client-tlsia 
endif

if ENABLE_OPENPGP
noinst_PROGRAMS += ex-serv-pgp
endif

if ENABLE_SRP
noinst_PROGRAMS += ex-client-srp ex-serv-srp
endif

noinst_LTLIBRARIES = libexamples.la

libexamples_la_SOURCES = ex-alert.c ex-pkcs12.c ex-rfc2818.c	\
	ex-session-info.c ex-x509-info.c ex-verify.c tcp.c
