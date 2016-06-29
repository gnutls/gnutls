## Process this file with automake to produce Makefile.in
# Copyright (C) 2007-2008, 2010, 2012 Free Software Foundation, Inc.
#
# Author: Simon Josefsson
#
# This file is part of GnuTLS.
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

EXTRA_DIST = ca-no-pathlen.pem no-ca-or-pathlen.pem aki-cert.pem \
	template-test.key template-test.pem template-test.tmpl \
	funny-spacing.pem ca-certs.pem dane-test.rr cert-ecc256.pem \
	bmpstring.pem template-utf8.pem template-utf8.tmpl \
	template-dn.tmpl template-dn.pem complex-cert.pem template-overflow.pem \
	template-overflow.tmpl template-overflow2.pem template-overflow2.tmpl \
	template-date.tmpl template-date.pem template-dn-err.tmpl \
	template-nc.tmpl template-nc.pem xmpp-othername.pem \
	suppressions.valgrind csr-invalid.der invalid-sig2.pem invalid-sig3.pem \
	invalid-sig.pem email-certs/chain.exclude.test.example.com email-certs/chain.test.example.com \
	email-certs/chain.invalid.example.com email-certs/chain.test.example.com-2 \
	single-ca.p7b single-ca.p7b.out full.p7b full.p7b.out detached.p7b \
	pkcs7-detached.txt p7-combined.out template-generalized.pem \
	template-generalized.tmpl privkey1.pem privkey2.pem privkey3.pem \
	name-constraints-ip.pem cert-invalid-utf8.der very-long-dn.pem \
	template-unique.tmpl template-unique.pem name-constraints-ip2.pem

dist_check_SCRIPTS = pathlen aki certtool invalid-sig email \
	pkcs7 privkey-import certtool-long-cn crl

if !HAVE_BUGGY_LIBIDN
dist_check_SCRIPTS += certtool-utf8
endif

if ENABLE_NON_SUITEB_CURVES
dist_check_SCRIPTS += crq
endif

if !WINDOWS
dist_check_SCRIPTS += template-test pem-decoding name-constraints
endif

if ENABLE_DANE
dist_check_SCRIPTS += dane
endif

TESTS = $(dist_check_SCRIPTS)

TESTS_ENVIRONMENT = EXEEXT=$(EXEEXT) \
	LC_ALL="C"				\
	VALGRIND="$(VALGRIND)" 			\
	LIBTOOL="$(LIBTOOL)"			\
	top_builddir="$(top_builddir)"		\
	srcdir="$(srcdir)"

if WINDOWS
TESTS_ENVIRONMENT += WINDOWS=1
endif
