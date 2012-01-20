## Process this file with automake to produce Makefile.in
# Copyright (C) 2000-2012 Free Software Foundation, Inc.
#
# Author: Nikos Mavrogiannopoulos
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

EXTRA_DIST = TODO certtool.cfg gnutls.ps gnutls.pdf gnutls.html	\
	doxygen/Doxyfile.in doxygen/Doxyfile.orig texinfo.css \
	gnutls-guile.pdf gnutls-guile.html

SUBDIRS = examples cyclo scripts manpages credentials latex
if ENABLE_GTK_DOC
SUBDIRS += reference
endif

info_TEXINFOS = gnutls.texi gnutls-guile.texi
gnutls_TEXINFOS = gnutls.texi fdl-1.3.texi				\
	cha-bib.texi cha-cert-auth.texi	cha-cert-auth2.texi		\
	cha-ciphersuites.texi cha-copying.texi cha-functions.texi	\
	cha-gtls-app.texi cha-internals.texi cha-intro-tls.texi		\
	cha-library.texi cha-preface.texi cha-programs.texi		\
	sec-tls-app.texi cha-errors.texi cha-support.texi		\
	cha-shared-key.texi cha-gtls-examples.texi

# Examples.
gnutls_TEXINFOS += examples/ex-client-anon.c				\
	examples/ex-session-info.c examples/ex-verify.c			\
	examples/ex-cert-select.c examples/ex-client-resume.c		\
	examples/ex-client-srp.c examples/ex-client-x509.c		\
	examples/ex-serv-x509.c examples/ex-serv-anon.c			\
	examples/ex-serv-pgp.c examples/ex-serv-srp.c			\
	examples/ex-alert.c examples/ex-x509-info.c examples/ex-crq.c	\
	examples/ex-pkcs12.c examples/ex-client-dtls.c

# Images.  Make sure there are eps + png + pdf of each, plus the source dia.
gnutls_TEXINFOS += gnutls-internals.dia gnutls-internals.eps		\
                   gnutls-internals.png
gnutls_TEXINFOS += gnutls-layers.dia gnutls-layers.eps			\
                   gnutls-layers.png
gnutls_TEXINFOS += gnutls-crypto-layers.dia gnutls-crypto-layers.eps	\
                   gnutls-crypto-layers.png
gnutls_TEXINFOS += gnutls-pgp.dia gnutls-pgp.eps gnutls-pgp.png
gnutls_TEXINFOS += gnutls-x509.dia gnutls-x509.eps gnutls-x509.png
gnutls_TEXINFOS += gnutls-logo.eps gnutls-logo.png
gnutls_TEXINFOS += pkcs11-vision.dia pkcs11-vision.eps pkcs11-vision.png

# Images.  Make sure there are eps + png + pdf of each, plus the source dia.
gnutls_TEXINFOS += gnutls-client-server-use-case.dia	\
	gnutls-client-server-use-case.eps		\
	gnutls-client-server-use-case.png
gnutls_TEXINFOS += gnutls-handshake-sequence.dia			\
	gnutls-handshake-sequence.eps gnutls-handshake-sequence.png
gnutls_TEXINFOS += gnutls-handshake-state.dia			\
	gnutls-handshake-state.eps gnutls-handshake-state.png
gnutls_TEXINFOS += gnutls-modauth.dia gnutls-modauth.eps	\
	gnutls-modauth.png

imagesdir = $(infodir)
images_DATA = \
	gnutls-handshake-state.png	\
	gnutls-layers.png gnutls-modauth.png gnutls-pgp.png	\
	gnutls-client-server-use-case.png			\
	gnutls-handshake-sequence.png gnutls-internals.png	\
	gnutls-logo.png gnutls-x509.png	\
	pkcs11-vision.png

AM_MAKEINFOFLAGS = -I $(top_srcdir)/doc
TEXI2DVI = texi2dvi $(AM_MAKEINFOFLAGS)
AM_MAKEINFOHTMLFLAGS = $(AM_MAKEINFOFLAGS) \
	--no-split --css-include=$(srcdir)/texinfo.css

MAINTAINERCLEANFILES =

# Generated texinfos.

gnutls_TEXINFOS += gnutls-api.texi x509-api.texi pgp-api.texi		\
	pkcs12-api.texi pkcs11-api.texi abstract-api.texi		\
	compat-api.texi dtls-api.texi crypto-api.texi ocsp-api.texi

MAINTAINERCLEANFILES += gnutls-api.texi x509-api.texi pgp-api.texi	\
	pkcs12-api.texi pkcs11-api.texi abstract-api.texi		\
	compat-api.texi dtls-api.texi crypto-api.texi ocsp-api.texi

gnutls-api.texi: $(top_srcdir)/lib/includes/gnutls/gnutls.h.in
	echo "" > $@-tmp
	for i in `$(top_srcdir)/doc/scripts/getfuncs.pl <$(top_srcdir)/lib/includes/gnutls/gnutls.h.in|sort|uniq`; do \
		echo -n "Creating documentation for $$i... " && \
		$(srcdir)/scripts/gdoc -texinfo \
			-function $$i \
			$(top_srcdir)/lib/*.c $(top_srcdir)/lib/*/*.c >> $@-tmp 2>/dev/null && \
		echo "ok"; \
	done
	mv -f $@-tmp $@

x509-api.texi: $(top_srcdir)/lib/includes/gnutls/x509.h
	echo "" > $@-tmp
	for i in `$(top_srcdir)/doc/scripts/getfuncs.pl <$(top_srcdir)/lib/includes/gnutls/x509.h|sort|uniq`; do \
		echo -n "Creating documentation for $$i... " && \
		$(srcdir)/scripts/gdoc -texinfo \
			-function $$i \
			$(top_srcdir)/lib/*.c $(top_srcdir)/lib/*/*.c >> $@-tmp 2>/dev/null && \
		echo "ok"; \
	done
	mv -f $@-tmp $@

pgp-api.texi: $(top_srcdir)/lib/includes/gnutls/openpgp.h
	echo "" > $@-tmp
	for i in `$(top_srcdir)/doc/scripts/getfuncs.pl <$(top_srcdir)/lib/includes/gnutls/openpgp.h|sort|uniq`; do \
		echo -n "Creating documentation for $$i... " && \
		$(srcdir)/scripts/gdoc -texinfo \
			-function $$i \
			$(top_srcdir)/lib/*.c $(top_srcdir)/lib/*/*.c >> $@-tmp 2>/dev/null && \
		echo "ok"; \
	done
	mv -f $@-tmp $@


pkcs12-api.texi: $(top_srcdir)/lib/includes/gnutls/pkcs12.h
	echo "" > $@-tmp
	for i in `$(top_srcdir)/doc/scripts/getfuncs.pl <$(top_srcdir)/lib/includes/gnutls/pkcs12.h|sort|uniq`; do \
		echo -n "Creating documentation for $$i... " && \
		$(srcdir)/scripts/gdoc -texinfo \
			-function $$i \
			$(top_srcdir)/lib/*.c $(top_srcdir)/lib/*/*.c >> $@-tmp 2>/dev/null && \
		echo "ok"; \
	done
	mv -f $@-tmp $@

pkcs11-api.texi: $(top_srcdir)/lib/includes/gnutls/pkcs11.h
	echo "" > $@-tmp
	for i in `$(top_srcdir)/doc/scripts/getfuncs.pl <$(top_srcdir)/lib/includes/gnutls/pkcs11.h|sort|uniq`; do \
		echo -n "Creating documentation for $$i... " && \
		$(srcdir)/scripts/gdoc -texinfo \
			-function $$i \
			$(top_srcdir)/lib/*.c $(top_srcdir)/lib/*/*.c >> $@-tmp 2>/dev/null && \
		echo "ok"; \
	done
	mv -f $@-tmp $@

abstract-api.texi: $(top_srcdir)/lib/includes/gnutls/abstract.h
	echo "" > $@-tmp
	for i in `$(top_srcdir)/doc/scripts/getfuncs.pl <$(top_srcdir)/lib/includes/gnutls/abstract.h|sort|uniq`; do \
		echo -n "Creating documentation for $$i... " && \
		$(srcdir)/scripts/gdoc -texinfo \
			-function $$i \
			$(top_srcdir)/lib/*.c $(top_srcdir)/lib/*/*.c >> $@-tmp 2>/dev/null && \
		echo "ok"; \
	done
	mv -f $@-tmp $@

compat-api.texi: $(top_srcdir)/lib/includes/gnutls/compat.h
	echo "" > $@-tmp
	for i in `$(top_srcdir)/doc/scripts/getfuncs.pl <$(top_srcdir)/lib/includes/gnutls/compat.h|sort|uniq`; do \
		echo -n "Creating documentation for $$i... " && \
		$(srcdir)/scripts/gdoc -texinfo \
			-function $$i \
			$(top_srcdir)/lib/*.c $(top_srcdir)/lib/*/*.c >> $@-tmp 2>/dev/null && \
		echo "ok"; \
	done
	mv -f $@-tmp $@

dtls-api.texi: $(top_srcdir)/lib/includes/gnutls/dtls.h
	echo "" > $@-tmp
	for i in `$(top_srcdir)/doc/scripts/getfuncs.pl <$(top_srcdir)/lib/includes/gnutls/dtls.h|sort|uniq`; do \
		echo -n "Creating documentation for $$i... " && \
		$(srcdir)/scripts/gdoc -texinfo \
			-function $$i \
			$(top_srcdir)/lib/*.c $(top_srcdir)/lib/*/*.c >> $@-tmp 2>/dev/null && \
		echo "ok"; \
	done
	mv -f $@-tmp $@

crypto-api.texi: $(top_srcdir)/lib/includes/gnutls/crypto.h
	echo "" > $@-tmp
	for i in `$(top_srcdir)/doc/scripts/getfuncs.pl <$(top_srcdir)/lib/includes/gnutls/crypto.h|sort|uniq`; do \
		echo -n "Creating documentation for $$i... " && \
		$(srcdir)/scripts/gdoc -texinfo \
			-function $$i \
			$(top_srcdir)/lib/*.c $(top_srcdir)/lib/*/*.c >> $@-tmp 2>/dev/null && \
		echo "ok"; \
	done
	mv -f $@-tmp $@

ocsp-api.texi: $(top_srcdir)/lib/includes/gnutls/ocsp.h
	echo "" > $@-tmp
	for i in `$(top_srcdir)/doc/scripts/getfuncs.pl <$(top_srcdir)/lib/includes/gnutls/ocsp.h|sort|uniq`; do \
		echo -n "Creating documentation for file $$i... " && \
		$(srcdir)/scripts/gdoc -texinfo \
			-function $$i \
			$(top_srcdir)/lib/*.c $(top_srcdir)/lib/*/*.c >> $@-tmp 2>/dev/null && \
		echo "ok"; \
	done
	mv -f $@-tmp $@

# Generated texinfos.
# for some reason it does not work when cross compiling
if !WINDOWS
gnutls_TEXINFOS += error_codes.texi algorithms.texi alerts.texi enums.texi
endif

DISTCLEANFILES = error_codes.texi algorithms.texi alerts.texi enums.texi

AM_CPPFLAGS = \
	-I$(top_builddir)/lib/includes -I$(top_srcdir)/lib/includes \
	-I$(top_builddir)/

EXTRA_PROGRAMS = errcodes printlist alert-printlist

errcodes_SOURCES = errcodes.c
errcodes_LDADD = ../lib/libgnutls.la ../gl/libgnu.la

printlist_SOURCES = printlist.c
printlist_LDADD = ../lib/libgnutls.la ../gl/libgnu.la

alert_printlist_SOURCES = alert-printlist.c
alert_printlist_LDADD = ../lib/libgnutls.la ../gl/libgnu.la

error_codes.texi: $(top_srcdir)/lib/gnutls_errors.c $(srcdir)/errcodes.c
	$(MAKE) $(builddir)/errcodes
	$(builddir)/errcodes > $@-tmp
	mv -f $@-tmp $@

algorithms.texi: $(top_srcdir)/lib/algorithms/ciphers.c $(srcdir)/printlist.c
	$(MAKE) $(builddir)/printlist
	$(builddir)/printlist > $@-tmp
	mv -f $@-tmp $@

alerts.texi: $(top_srcdir)/lib/gnutls_alert.c $(srcdir)/alert-printlist.c
	$(MAKE) $(builddir)/alert-printlist
	$(builddir)/alert-printlist > $@-tmp
	mv -f $@-tmp $@

enums.texi: $(srcdir)/../lib/includes/gnutls/*.h $(builddir)/../lib/includes/gnutls/*.h
	echo "" > $@-tmp
	for i in $^; do \
		echo -n "Creating documentation for $$i... " && \
		$(srcdir)/scripts/gdoc -texinfo $$i >> $@-tmp && \
		echo "ok"; \
	done
	mv -f $@-tmp $@

ENUMS =
ENUMS += enums/gnutls_alert_description_t
ENUMS += enums/gnutls_alert_level_t
ENUMS += enums/gnutls_certificate_import_flags
ENUMS += enums/gnutls_certificate_print_formats_t
ENUMS += enums/gnutls_certificate_request_t
ENUMS += enums/gnutls_certificate_status_t
ENUMS += enums/gnutls_certificate_type_t
ENUMS += enums/gnutls_certificate_verify_flags
ENUMS += enums/gnutls_channel_binding_t
ENUMS += enums/gnutls_cipher_algorithm_t
ENUMS += enums/gnutls_close_request_t
ENUMS += enums/gnutls_compression_method_t
ENUMS += enums/gnutls_credentials_type_t
ENUMS += enums/gnutls_digest_algorithm_t
ENUMS += enums/gnutls_ecc_curve_t
ENUMS += enums/gnutls_handshake_description_t
ENUMS += enums/gnutls_kx_algorithm_t
ENUMS += enums/gnutls_mac_algorithm_t
ENUMS += enums/gnutls_openpgp_crt_fmt_t
ENUMS += enums/gnutls_openpgp_crt_status_t
ENUMS += enums/gnutls_params_type_t
ENUMS += enums/gnutls_pk_algorithm_t
ENUMS += enums/gnutls_pkcs11_obj_attr_t
ENUMS += enums/gnutls_pkcs11_obj_info_t
ENUMS += enums/gnutls_pkcs11_obj_type_t
ENUMS += enums/gnutls_pkcs11_token_info_t
ENUMS += enums/gnutls_pkcs12_bag_type_t
ENUMS += enums/gnutls_pkcs_encrypt_flags_t
ENUMS += enums/gnutls_privkey_type_t
ENUMS += enums/gnutls_protocol_t
ENUMS += enums/gnutls_psk_key_flags
ENUMS += enums/gnutls_rnd_level_t
ENUMS += enums/gnutls_sec_param_t
ENUMS += enums/gnutls_server_name_type_t
ENUMS += enums/gnutls_sign_algorithm_t
ENUMS += enums/gnutls_supplemental_data_format_type_t
ENUMS += enums/gnutls_x509_crt_fmt_t
ENUMS += enums/gnutls_x509_subject_alt_name_t

gnutls_TEXINFOS += $(ENUMS)
DISTCLEANFILES += $(ENUMS)

$(ENUMS): enums.texi
	$(MAKE) compare-makefile
	-mkdir enums
	$(srcdir)/scripts/split-texi.pl enums enum < enums.texi

compare-makefile:
	ENUMS=`grep '^@c ' enums.texi | sed 's/@c //g' | sort`; \
	STR=""; \
	for i in $$ENUMS; do \
		STR="$$STR\nENUMS += enums/$$i"; \
	done; \
	grep -v -e '^ENUMS += ' $(srcdir)/Makefile.am | \
		perl -p -e "s,^ENUMS =,ENUMS =$$STR," > tmp-$@; \
	diff -u $(srcdir)/Makefile.am tmp-$@
	rm -f tmp-$@

.PHONY: compare-makefile

# Guile texinfos.

guile_texi = core.c.texi
BUILT_SOURCES        = $(guile_texi)
MAINTAINERCLEANFILES += $(guile_texi)
EXTRA_DIST           += $(guile_texi) extract-guile-c-doc.scm
guile_TEXINFOS       = gnutls-guile.texi $(guile_texi)

if HAVE_GUILE

GUILE_FOR_BUILD =				\
  GUILE_AUTO_COMPILE=0				\
  $(GUILE) -L $(top_srcdir)/guile/modules

SNARF_CPPFLAGS = -I$(top_srcdir) -I$(top_builddir)			\
	 -I$(top_srcdir)/lib/includes -I$(top_builddir)/lib/includes	\
	 -I$(top_srcdir)/extra/includes				\
         -I$(top_srcdir)/guile/src -I$(top_builddir)/guile/src		\
	 $(GUILE_CFLAGS)

core.c.texi: $(top_srcdir)/guile/src/core.c
	$(MAKE) -C ../guile/src built-sources &&			\
	$(GUILE_FOR_BUILD) -l "$(srcdir)/extract-guile-c-doc.scm"	\
	   -e '(apply main (cdr (command-line)))'			\
	   -- "$^" "$(CPP)" "$(SNARF_CPPFLAGS) $(CPPFLAGS)"		\
	   > "$@"

else !HAVE_GUILE

core.c.texi:
	echo "(Guile not available, documentation not generated.)" > $@

endif !HAVE_GUILE
