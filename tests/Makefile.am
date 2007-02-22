## Process this file with automake to produce Makefile.in
# Copyright (C) 2004, 2005, 2006, 2007 Free Software Foundation
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

SUBDIRS = rsa-md5-collision pkcs1-padding pkcs8-decode pkcs12-decode	\
	userid pathlen key-id sha2 hostname-check

AM_CPPFLAGS = -I$(top_srcdir)/lgl -I$(top_builddir)/lgl			\
	-I$(top_srcdir)/gl -I$(top_builddir)/gl				\
	-I$(top_srcdir)/includes -I$(top_builddir)/includes
AM_LDFLAGS = -no-install
LDADD = ../lib/libgnutls.la ../gl/libgnu.la ../lgl/liblgnu.la libutils.la

noinst_LTLIBRARIES = libutils.la
libutils_la_SOURCES = utils.h utils.c

ctests = simple openssl gc set_pkcs12_cred certder	\
	certificate_set_x509_crl dn
openssl_LDADD = $(LDADD) ../libextra/libgnutls-openssl.la
if HAVE_FORK
ctests +=  anonself pskself dhepskself tlsia resume
tlsia_LDADD = $(LDADD) ../libextra/libgnutls-extra.la @LTLIBREADLINE@
endif
gc_LDADD = $(LDADD) $(LIBGCRYPT_LIBS)

check_PROGRAMS = $(ctests)

TESTS = $(ctests)

TESTS_ENVIRONMENT = \
	PKCS12FILE=$(srcdir)/pkcs12-decode/client.p12	\
	PKCS12PASSWORD=foobar \
	$(VALGRIND)
