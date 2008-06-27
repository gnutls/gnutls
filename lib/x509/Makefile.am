## Process this file with automake to produce Makefile.in
# Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008 Free Software Foundation
#
# This file is part of GNUTLS.
#
# The GNUTLS library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA

INCLUDES = \
	-I$(top_srcdir)/lgl -I$(top_builddir)/lgl			\
	-I$(top_srcdir)/libextra -I$(top_srcdir)/lib/minitasn1		\
	-I$(top_srcdir)/libextra/openpgp/				\
	-I$(top_srcdir)/libextra/opencdk -I$(top_srcdir)/lib		\
	-I$(top_srcdir)/includes -I$(top_builddir)/includes		\
	$(LIBOPENCDK_CFLAGS) $(LIBTASN1_CFLAGS) $(LIBGCRYPT_CFLAGS)

noinst_LTLIBRARIES = libgnutls_x509.la

libgnutls_x509_la_SOURCES = crl.c dn.c common.c x509.c extensions.c	\
	rfc2818_hostname.c verify.c mpi.c privkey.c pkcs7.c	\
	crq.c sign.c privkey_pkcs8.c pkcs12.c pkcs12_bag.c		\
	pkcs12_encr.c x509_write.c crl_write.c common.h x509_int.h	\
	output.c

EXTRA_DIST = x509-api.texi

x509-api.texi: $(libgnutls_x509_la_SOURCES)
	@echo "" > x509-api.texi
	@for i in $(libgnutls_x509_la_SOURCES); do \
		echo -n "Creating documentation for file $$i... " && \
		$(top_srcdir)/doc/scripts/gdoc -texinfo $$i >> x509-api.texi && \
		echo "ok"; \
	done

dist-hook: x509-api.texi
