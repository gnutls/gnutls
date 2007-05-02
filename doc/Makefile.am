## Process this file with automake to produce Makefile.in
# Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007 Free Software Foundation
#
# Author: Nikos Mavroyanopoulos
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

EXTRA_DIST = TODO README.CVS README.autoconf certtool.cfg \
	gnutls.ps gnutls.pdf gnutls.html
SUBDIRS = examples scripts manpages
if ENABLE_GTK_DOC
SUBDIRS += reference
endif

info_TEXINFOS = gnutls.texi
gnutls_TEXINFOS = gnutls.texi signatures.texi fdl.texi lgpl.texi	\
	gpl.texi error_codes.texi gnutls-api.texi p11-api.texi		\
	gnutls-extra-api.texi ia-api.texi x509-api.texi pgp-api.texi	\
	my-bib-macros.texi examples/ex-client1.c examples/ex-client2.c	\
	examples/ex-session-info.c examples/ex-verify.c			\
	examples/ex-cert-select.c examples/ex-client-resume.c		\
	examples/ex-client-srp.c examples/ex-client-tlsia.c		\
	examples/ex-rfc2818.c examples/ex-serv1.c			\
	examples/ex-serv-export.c examples/ex-serv-anon.c		\
	examples/ex-serv-pgp.c examples/ex-serv-srp.c			\
	examples/ex-alert.c examples/ex-x509-info.c examples/ex-crq.c	\
	examples/ex-pkcs12.c layers.eps layers.png pgp1.eps pgp1.png	\
	x509-1.eps x509-1.png gnutls-logo.eps gnutls-logo.png		\
	gnutls-logo.pdf

# Internal manual.
gnutls_TEXINFOS += internals.texi internals.eps internals.png		\
	arch/certificate-user-use-case.dia				\
	arch/client-server-use-case.dia arch/objects.dia		\
	arch/certificate-user-use-case.eps				\
	arch/certificate-user-use-case.pdf				\
	arch/certificate-user-use-case.png				\
	arch/client-server-use-case.eps					\
	arch/client-server-use-case.pdf					\
	arch/client-server-use-case.png arch/extensions_st.dia		\
	arch/extensions_st.eps arch/extensions_st.pdf			\
	arch/extensions_st.png arch/handshake-sequence.dia		\
	arch/handshake-sequence.eps arch/handshake-sequence.pdf		\
	arch/handshake-sequence.png arch/handshake-state.dia		\
	arch/handshake-state.eps arch/handshake-state.pdf		\
	arch/handshake-state.png arch/mod_auth_st.dia			\
	arch/mod_auth_st.eps arch/mod_auth_st.pdf arch/mod_auth_st.png	\
	arch/objects.eps arch/objects.pdf arch/objects.png

AM_MAKEINFOFLAGS = -I $(top_srcdir)/doc
TEXI2DVI = texi2dvi $(AM_MAKEINFOFLAGS)
AM_MAKEINFOHTMLFLAGS = $(AM_MAKEINFOFLAGS) \
	--no-split

../lib/gnutls-api.texi:
	cd ../lib && make gnutls-api.texi

../libextra/gnutls-extra-api.texi:
	cd ../libextra && make gnutls-extra-api.texi

../lib/x509/x509-api.texi:
	cd ../lib/x509 && make x509-api.texi

../libextra/openpgp/pgp-api.texi:
	cd ../libextra/openpgp && make pgp-api.texi

../libextra/ia-api.texi:
	cd ../libextra && make ia-api.texi

../pkcs11/p11-api.texi:
	cd ../pkcs11 && make p11-api.texi

gnutls-api.texi: ../lib/gnutls-api.texi
	-$(srcdir)/scripts/sort2.pl < ../lib/gnutls-api.texi > gnutls-api.texi

gnutls-extra-api.texi: ../libextra/gnutls-extra-api.texi
	-$(srcdir)/scripts/sort2.pl < ../libextra/gnutls-extra-api.texi > gnutls-extra-api.texi

x509-api.texi: ../lib/x509/x509-api.texi
	-$(srcdir)/scripts/sort2.pl < ../lib/x509/x509-api.texi > x509-api.texi

pgp-api.texi: ../libextra/openpgp/pgp-api.texi
	-$(srcdir)/scripts/sort2.pl < ../libextra/openpgp/pgp-api.texi > pgp-api.texi

ia-api.texi: ../libextra/ia-api.texi
	-$(srcdir)/scripts/sort2.pl < ../libextra/ia-api.texi > ia-api.texi

p11-api.texi: ../pkcs11/p11-api.texi
	-$(srcdir)/scripts/sort2.pl < ../pkcs11/p11-api.texi > p11-api.texi

error_codes.texi: ../lib/gnutls_errors.c ../src/errcodes.c
	-../src/errcodes > error_codes.texi
