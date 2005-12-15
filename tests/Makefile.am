## Process this file with automake to produce Makefile.in
# Copyright (C) 2004, 2005 Free Software Foundation
#
# Author: Simon Josefsson
#
# This file is part of GNUTLS.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
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

AM_CPPFLAGS = -I../gl -I$(top_srcdir)/gl -I../includes -I$(top_srcdir)/includes
AM_LDFLAGS = -no-install
LDADD = ../lib/libgnutls.la ../gl/libgnu.la libutils.la

noinst_LTLIBRARIES = libutils.la
libutils_la_SOURCES = utils.h utils.c

# For pkcs12_neon.
EXTRA_DIST = client.p12 noclient.p12 unclient.p12

# For pkcs8.
EXTRA_DIST += encpkcs8.pem unencpkcs8.pem enc2pkcs8.pem

openssl_LDADD = $(LDADD) ../libextra/libgnutls-openssl.la
tlsia_LDADD = $(LDADD) ../libextra/libgnutls-extra.la \
	../gl/libgnu.la @LTLIBREADLINE@

ctests = simple anonself pskself openssl gc dhepskself set_pkcs12_cred tlsia
TESTS = pkcs12_neon pkcs8 $(ctests)
check_PROGRAMS = $(ctests)
dist_check_SCRIPTS = pkcs12_neon pkcs8

TESTS_ENVIRONMENT = \
	PKCS12FILE=$(srcdir)/client.p12	\
	PKCS12PASSWORD=foobar
