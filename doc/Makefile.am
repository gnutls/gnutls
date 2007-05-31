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

EXTRA_DIST = TODO README.CVS README.autoconf certtool.cfg	\
	gnutls.ps gnutls.pdf gnutls.html			\
        extract-guile-c-doc.scm
SUBDIRS = examples scripts manpages
if ENABLE_GTK_DOC
SUBDIRS += reference
endif

info_TEXINFOS = gnutls.texi
gnutls_TEXINFOS = gnutls.texi signatures.texi fdl.texi lgpl.texi	\
	gpl.texi error_codes.texi gnutls-api.texi			\
	gnutls-extra-api.texi ia-api.texi x509-api.texi pgp-api.texi	\
	my-bib-macros.texi examples/ex-client1.c examples/ex-client2.c	\
	examples/ex-session-info.c examples/ex-verify.c			\
	examples/ex-cert-select.c examples/ex-client-resume.c		\
	examples/ex-client-srp.c examples/ex-client-tlsia.c		\
	examples/ex-rfc2818.c examples/ex-serv1.c			\
	examples/ex-serv-export.c examples/ex-serv-anon.c		\
	examples/ex-serv-pgp.c examples/ex-serv-srp.c			\
	examples/ex-alert.c examples/ex-x509-info.c examples/ex-crq.c	\
	examples/ex-pkcs12.c						\
	guile.texi

# Images.  Make sure there are eps + png + pdf of each.
gnutls_TEXINFOS += layers.eps layers.png layers.pdf
gnutls_TEXINFOS += pgp1.eps pgp1.png pgp1.pdf
gnutls_TEXINFOS += x509-1.eps x509-1.png x509-1.pdf
gnutls_TEXINFOS += gnutls-logo.eps gnutls-logo.png gnutls-logo.pdf

# Internal manual.
gnutls_TEXINFOS += internals.texi 	

# Images.  Make sure there are eps + png + pdf of each.
gnutls_TEXINFOS += internals.eps internals.png internals.pdf
gnutls_TEXINFOS += arch/certificate-user-use-case.dia	\
	arch/certificate-user-use-case.eps		\
	arch/certificate-user-use-case.pdf		\
	arch/certificate-user-use-case.png
gnutls_TEXINFOS += arch/client-server-use-case.dia	\
	arch/client-server-use-case.eps			\
	arch/client-server-use-case.pdf			\
	arch/client-server-use-case.png
gnutls_TEXINFOS += arch/extensions_st.dia arch/extensions_st.eps	\
	arch/extensions_st.pdf arch/extensions_st.png
gnutls_TEXINFOS += arch/handshake-sequence.dia				\
	arch/handshake-sequence.eps arch/handshake-sequence.pdf		\
	arch/handshake-sequence.png
gnutls_TEXINFOS += arch/handshake-state.dia arch/handshake-state.eps	\
	arch/handshake-state.pdf arch/handshake-state.png
gnutls_TEXINFOS += arch/mod_auth_st.dia arch/mod_auth_st.eps		\
	arch/mod_auth_st.pdf arch/mod_auth_st.png
gnutls_TEXINFOS += arch/objects.dia arch/objects.eps arch/objects.pdf	\
	arch/objects.png

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

error_codes.texi: ../lib/gnutls_errors.c ../src/errcodes.c
	-../src/errcodes > error_codes.texi


guile_texi     = core.c.texi extra.c.texi
BUILT_SOURCES  = $(guile_texi)
CLEANFILES     = $(guile_texi)
EXTRA_DIST    += $(guile_texi)

if HAVE_GUILE

#
# Guile documentation extraction from C code.
#

GUILE_FOR_BUILD = $(GUILE) -L $(top_srcdir)/guile/modules

SNARF_CPPFLAGS = -I$(top_srcdir)/guile/src -I$(top_builddir)/guile/src


core.c.texi: $(top_srcdir)/guile/src/core.c
	$(GUILE_FOR_BUILD) -l "$(srcdir)/extract-guile-c-doc.scm"	\
	   -e '(apply main (cdr (command-line)))'			\
	   -- "$^" "$(CPP)" "$(SNARF_CPPFLAGS) $(CPPFLAGS)"		\
	   > "$@"

extra.c.texi: $(top_srcdir)/guile/src/extra.c
	$(GUILE_FOR_BUILD) -l "$(srcdir)/extract-guile-c-doc.scm"	\
	   -e '(apply main (cdr (command-line)))'			\
	   -- "$^" "$(CPP)" "$(SNARF_CPPFLAGS) $(CPPFLAGS)"		\
	   > "$@"


else !HAVE_GUILE

core.c.texi:
	echo "(Guile not available, documentation not generated.)" > $@

extra.c.texi:
	echo "(Guile not available, documentation not generated.)" > $@


endif !HAVE_GUILE
