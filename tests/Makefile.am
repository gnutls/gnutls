## Process this file with automake to produce Makefile.in
# Copyright (C) 2004, 2005, 2006, 2007, 2008 Free Software Foundation
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

SUBDIRS = rsa-md5-collision pkcs1-padding pkcs8-decode pkcs12-decode	\
	userid pathlen key-id sha2 hostname-check

if ENABLE_OPENPGP
SUBDIRS += openpgp openpgp-certs
endif

EXTRA_DIST = libgcrypt.supp

AM_CPPFLAGS = -I$(top_srcdir)/lgl -I$(top_builddir)/lgl			\
	-I$(top_srcdir)/gl -I$(top_builddir)/gl				\
	-I$(top_srcdir)/includes -I$(top_builddir)/includes		\
	-I$(top_srcdir)/lib 						\
	-I$(top_srcdir)/doc/examples
AM_LDFLAGS = -no-install
LDADD = ../lib/libgnutls.la ../gl/libgnu.la ../lgl/liblgnu.la libutils.la

if ENABLE_MINITASN1

AM_CPPFLAGS += -I$(top_srcdir)/lib/minitasn1

endif

noinst_LTLIBRARIES = libutils.la
libutils_la_SOURCES = utils.h utils.c

ctests = simple openssl gc set_pkcs12_cred certder mpi			\
	certificate_set_x509_crl dn parse_ca moredn crypto_rng mini	\
	finished
openssl_LDADD = $(LDADD) ../libextra/libgnutls-openssl.la

if ENABLE_OPENPGP
ctests += pgps2kgnu 
endif

if HAVE_FORK
ctests += x509self x509signself x509dn anonself pskself dhepskself	\
	tlsia resume netconf-psk setcredcrash

if ENABLE_OPENPGP
ctests += openpgpself 
endif

tlsia_LDADD = ../libextra/libgnutls-extra.la $(LDADD) @LTLIBREADLINE@
endif

if ENABLE_OPRFI
ctests +=  oprfi
endif

gc_LDADD = $(LDADD) $(LIBGCRYPT_LIBS)

check_PROGRAMS = $(ctests)

TESTS = $(ctests)

TESTS_ENVIRONMENT = \
	PKCS12FILE=$(srcdir)/pkcs12-decode/client.p12	\
	PKCS12PASSWORD=foobar \
	$(VALGRIND)
