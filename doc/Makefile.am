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

EXTRA_DIST = TODO certtool.cfg gnutls.pdf gnutls.html	\
	doxygen/Doxyfile.in doxygen/Doxyfile.orig texinfo.css \
	gnutls-guile.pdf gnutls-guile.html stamp_enums stamp_functions

SUBDIRS = examples cyclo scripts manpages credentials latex
if ENABLE_GTK_DOC
SUBDIRS += reference
endif

SRC_DEF_CLI = 
SRC_DEF_CLI_DEBUG = 
SRC_DEF_SERV = 
SRC_DEF_CERTTOOL = 
SRC_DEF_OCSPTOOL = 
SRC_DEF_SRPTOOL = 
SRC_DEF_PSKTOOL = 
SRC_DEF_P11TOOL = 
if WANT_TEST_SUITE
SRC_DEF_CLI += ../src/cli-args.def
SRC_DEF_CLI_DEBUG += ../src/cli-debug-args.def
SRC_DEF_SERV += ../src/serv-args.def
SRC_DEF_CERTTOOL += ../src/certtool-args.def
SRC_DEF_OCSPTOOL += ../src/ocsptool-args.def
SRC_DEF_SRPTOOL += ../src/srptool-args.def
SRC_DEF_PSKTOOL += ../src/psk-args.def
SRC_DEF_P11TOOL += ../src/p11tool-args.def
endif

invoke-gnutls-cli.texi: $(SRC_DEF_CLI)
	@-cd ../src/ && autogen -Tagtexi-cmd.tpl $< && \
	rm -f ../doc/$@ && \
	../doc/scripts/cleanup-autogen.pl <../src/$@ >../doc/$@.tmp && \
	mv -f ../doc/$@.tmp ../doc/$@ && \
	rm -f ../src/$@

invoke-gnutls-cli-debug.texi: $(SRC_DEF_CLI_DEBUG)
	@-cd ../src/ && autogen -Tagtexi-cmd.tpl $< && \
	rm -f ../doc/$@ && \
	../doc/scripts/cleanup-autogen.pl <../src/$@ >../doc/$@.tmp && \
	mv -f ../doc/$@.tmp ../doc/$@ && \
	rm -f ../src/$@

invoke-gnutls-serv.texi: $(SRC_DEF_SERV)
	@-cd ../src/ && autogen -Tagtexi-cmd.tpl $< && \
	rm -f ../doc/$@ && \
	../doc/scripts/cleanup-autogen.pl <../src/$@ >../doc/$@.tmp && \
	mv -f ../doc/$@.tmp ../doc/$@ && \
	rm -f ../src/$@

invoke-certtool.texi: $(SRC_DEF_CERTTOOL)
	@-cd ../src/ && autogen -Tagtexi-cmd.tpl $< && \
	rm -f ../doc/$@ && \
	../doc/scripts/cleanup-autogen.pl <../src/$@ >../doc/$@.tmp && \
	mv -f ../doc/$@.tmp ../doc/$@ && \
	rm -f ../src/$@

invoke-ocsptool.texi: $(SRC_DEF_OCSPTOOL)
	@-cd ../src/ && autogen -Tagtexi-cmd.tpl $< && \
	rm -f ../doc/$@ && \
	../doc/scripts/cleanup-autogen.pl <../src/$@ >../doc/$@.tmp && \
	mv -f ../doc/$@.tmp ../doc/$@ && \
	rm -f ../src/$@

invoke-srptool.texi: $(SRC_DEF_SRPTOOL)
	@-cd ../src/ && autogen -Tagtexi-cmd.tpl $< && \
	rm -f ../doc/$@ && \
	../doc/scripts/cleanup-autogen.pl <../src/$@ >../doc/$@.tmp && \
	mv -f ../doc/$@.tmp ../doc/$@ && \
	rm -f ../src/$@ && \
	sed -i 's/@subheading/@subsubheading/g' ../doc/$@ && \
	sed -i 's/@section/@subsection/g' ../doc/$@

invoke-psktool.texi: $(SRC_DEF_PSKTOOL)
	@-cd ../src/ && autogen -Tagtexi-cmd.tpl $< && \
	rm -f ../doc/$@ && \
	../doc/scripts/cleanup-autogen.pl <../src/$@ >../doc/$@.tmp && \
	mv -f ../doc/$@.tmp ../doc/$@ && \
	rm -f ../src/$@ && \
	sed -i 's/@subheading/@subsubheading/g' ../doc/$@ && \
	sed -i 's/@section/@subsection/g' ../doc/$@

invoke-p11tool.texi: $(SRC_DEF_P11TOOL)
	@-cd ../src/ && autogen -Tagtexi-cmd.tpl $< && \
	rm -f ../doc/$@ && \
	../doc/scripts/cleanup-autogen.pl <../src/$@ >../doc/$@.tmp && \
	mv -f ../doc/$@.tmp ../doc/$@ && \
	rm -f ../src/$@ && \
	sed -i 's/@subheading/@subsubheading/g' ../doc/$@ && \
	sed -i 's/@section/@subsection/g' ../doc/$@

info_TEXINFOS = gnutls.texi gnutls-guile.texi
gnutls_TEXINFOS = gnutls.texi fdl-1.3.texi				\
	cha-bib.texi cha-cert-auth.texi	cha-cert-auth2.texi		\
	cha-ciphersuites.texi cha-copying.texi cha-functions.texi	\
	cha-gtls-app.texi cha-internals.texi cha-intro-tls.texi		\
	cha-library.texi cha-preface.texi cha-programs.texi		\
	sec-tls-app.texi cha-errors.texi cha-support.texi		\
	cha-shared-key.texi cha-gtls-examples.texi cha-upgrade.texi

gnutls_TEXINFOS += invoke-gnutls-cli.texi invoke-gnutls-cli-debug.texi \
	invoke-gnutls-serv.texi invoke-certtool.texi invoke-srptool.texi \
	invoke-ocsptool.texi invoke-psktool.texi invoke-p11tool.texi

gnutls_TEXINFOS += stamp_functions

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

HEADER_FILES = $(top_srcdir)/lib/includes/gnutls/gnutls.h.in \
	$(top_srcdir)/lib/includes/gnutls/x509.h $(top_srcdir)/lib/includes/gnutls/openpgp.h \
	$(top_srcdir)/lib/includes/gnutls/pkcs12.h $(top_srcdir)/lib/includes/gnutls/pkcs11.h \
	$(top_srcdir)/lib/includes/gnutls/abstract.h $(top_srcdir)/lib/includes/gnutls/compat.h \
	$(top_srcdir)/lib/includes/gnutls/dtls.h $(top_srcdir)/lib/includes/gnutls/crypto.h \
	$(top_srcdir)/lib/includes/gnutls/ocsp.h

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

errcodes_SOURCES = errcodes.c common.c common.h
errcodes_LDADD = ../lib/libgnutls.la ../gl/libgnu.la

printlist_SOURCES = printlist.c common.c common.h
printlist_LDADD = ../lib/libgnutls.la ../gl/libgnu.la

alert_printlist_SOURCES = alert-printlist.c common.c common.h
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

enums.texi: $(HEADER_FILES)
	echo "" > $@-tmp
	for i in $^; do \
		echo -n "Creating documentation for $$i... " && \
		$(srcdir)/scripts/gdoc -texinfo $$i >> $@-tmp && \
		echo "ok"; \
	done
	mv -f $@-tmp $@

gnutls_TEXINFOS += $(ENUMS) $(FUNCS)
DISTCLEANFILES += $(ENUMS) stamp_enums stamp_functions

stamp_functions: gnutls-api.texi x509-api.texi pgp-api.texi pkcs12-api.texi pkcs11-api.texi abstract-api.texi compat-api.texi dtls-api.texi crypto-api.texi ocsp-api.texi
	-mkdir functions
	for i in $^; do \
		$(srcdir)/scripts/split-texi.pl functions < $$i; \
	done
	sed -i 's/\@anchor{.*//g' functions/*
	sed -i 's/\@subheading.*//g' functions/*
	echo $@ > $@
	$(MAKE) compare-makefile

stamp_enums: enums.texi
	-mkdir enums
	$(srcdir)/scripts/split-texi.pl enums enum < enums.texi
	echo $@ > $@
	$(MAKE) compare-makefile

$(ENUMS): stamp_enums

$(FUNCS): stamp_functions

compare-makefile: enums.texi
	ENUMS=`grep '^@c ' enums.texi | sed 's/@c //g' | sort`; \
	STR=""; \
	for i in $$ENUMS; do \
		STR="$$STR\nENUMS += enums/$$i"; \
	done; \
	grep -v -e '^ENUMS += ' $(srcdir)/Makefile.am | \
		perl -p -e "s,^ENUMS =,ENUMS =$$STR," > tmp-$@; \
	diff -u $(srcdir)/Makefile.am tmp-$@
	rm -f tmp-$@
	FUNCS=`cat $(top_srcdir)/lib/includes/gnutls/*.h | $(top_srcdir)/doc/scripts/getfuncs.pl`; \
	MANS=""; \
	for i in $$FUNCS; do \
		MANS="$$MANS\nFUNCS += functions/$$i"; \
	done; \
	grep -v -e '^FUNCS += ' Makefile.am | \
		perl -p -e "s,^FUNCS =,FUNCS =$$MANS," > tmp-$@; \
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

gnutls.xml: epub.texi
	makeinfo --docbook $<
	sed -i 's/\&\#8226;//g' $@

gnutls.epub: gnutls.xml
	dbtoepub $<
	epub-fix --delete-unmanifested gnutls.epub

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

FUNCS =
FUNCS += functions/gnutls_pubkey_init
FUNCS += functions/gnutls_pubkey_deinit
FUNCS += functions/gnutls_pubkey_get_pk_algorithm
FUNCS += functions/gnutls_pubkey_import_x509
FUNCS += functions/gnutls_pubkey_import_pkcs11
FUNCS += functions/gnutls_pubkey_import_openpgp
FUNCS += functions/gnutls_pubkey_import_privkey
FUNCS += functions/gnutls_pubkey_get_preferred_hash_algorithm
FUNCS += functions/gnutls_pubkey_get_pk_rsa_raw
FUNCS += functions/gnutls_pubkey_get_pk_dsa_raw
FUNCS += functions/gnutls_pubkey_get_pk_ecc_raw
FUNCS += functions/gnutls_pubkey_get_pk_ecc_x962
FUNCS += functions/gnutls_pubkey_export
FUNCS += functions/gnutls_pubkey_get_key_id
FUNCS += functions/gnutls_pubkey_get_openpgp_key_id
FUNCS += functions/gnutls_pubkey_get_key_usage
FUNCS += functions/gnutls_pubkey_set_key_usage
FUNCS += functions/gnutls_pubkey_import
FUNCS += functions/gnutls_pubkey_import_pkcs11_url
FUNCS += functions/gnutls_pubkey_import_dsa_raw
FUNCS += functions/gnutls_pubkey_import_rsa_raw
FUNCS += functions/gnutls_pubkey_import_ecc_x962
FUNCS += functions/gnutls_pubkey_import_ecc_raw
FUNCS += functions/gnutls_pubkey_encrypt_data
FUNCS += functions/gnutls_x509_crt_set_pubkey
FUNCS += functions/gnutls_x509_crq_set_pubkey
FUNCS += functions/gnutls_pubkey_verify_hash
FUNCS += functions/gnutls_pubkey_verify_hash2
FUNCS += functions/gnutls_pubkey_get_verify_algorithm
FUNCS += functions/gnutls_pubkey_verify_data
FUNCS += functions/gnutls_pubkey_verify_data2
FUNCS += functions/gnutls_privkey_init
FUNCS += functions/gnutls_privkey_deinit
FUNCS += functions/gnutls_privkey_get_pk_algorithm
FUNCS += functions/gnutls_privkey_get_type
FUNCS += functions/gnutls_privkey_import_pkcs11
FUNCS += functions/gnutls_privkey_import_x509
FUNCS += functions/gnutls_privkey_import_openpgp
FUNCS += functions/gnutls_privkey_import_ext
FUNCS += functions/gnutls_privkey_sign_data
FUNCS += functions/gnutls_privkey_sign_hash
FUNCS += functions/gnutls_privkey_decrypt_data
FUNCS += functions/gnutls_x509_crt_privkey_sign
FUNCS += functions/gnutls_x509_crl_privkey_sign
FUNCS += functions/gnutls_x509_crq_privkey_sign
FUNCS += functions/gnutls_pcert_import_x509
FUNCS += functions/gnutls_pcert_list_import_x509_raw
FUNCS += functions/gnutls_pcert_import_x509_raw
FUNCS += functions/gnutls_pcert_import_openpgp_raw
FUNCS += functions/gnutls_pcert_import_openpgp
FUNCS += functions/gnutls_pcert_deinit
FUNCS += functions/gnutls_certificate_set_retrieve_function2
FUNCS += functions/gnutls_certificate_set_key
FUNCS += functions/gnutls_sign_callback_set
FUNCS += functions/gnutls_sign_callback_get
FUNCS += functions/gnutls_x509_privkey_sign_hash
FUNCS += functions/gnutls_openpgp_privkey_sign_hash
FUNCS += functions/gnutls_x509_privkey_sign_data
FUNCS += functions/gnutls_x509_crt_verify_data
FUNCS += functions/gnutls_x509_crt_verify_hash
FUNCS += functions/gnutls_x509_crt_get_verify_algorithm
FUNCS += functions/gnutls_x509_crt_get_preferred_hash_algorithm
FUNCS += functions/gnutls_x509_crq_sign
FUNCS += functions/gnutls_x509_crl_sign
FUNCS += functions/gnutls_cipher_set_priority
FUNCS += functions/gnutls_mac_set_priority
FUNCS += functions/gnutls_compression_set_priority
FUNCS += functions/gnutls_kx_set_priority
FUNCS += functions/gnutls_protocol_set_priority
FUNCS += functions/gnutls_certificate_type_set_priority
FUNCS += functions/gnutls_rsa_params_init
FUNCS += functions/gnutls_rsa_params_deinit
FUNCS += functions/gnutls_rsa_params_cpy
FUNCS += functions/gnutls_rsa_params_import_raw
FUNCS += functions/gnutls_rsa_params_generate2
FUNCS += functions/gnutls_rsa_params_export_raw
FUNCS += functions/gnutls_rsa_params_export_pkcs1
FUNCS += functions/gnutls_rsa_params_import_pkcs1
FUNCS += functions/gnutls_rsa_export_get_pubkey
FUNCS += functions/gnutls_rsa_export_get_modulus_bits
FUNCS += functions/gnutls_set_default_export_priority
FUNCS += functions/gnutls_certificate_set_rsa_export_params
FUNCS += functions/gnutls_cipher_init
FUNCS += functions/gnutls_cipher_encrypt
FUNCS += functions/gnutls_cipher_decrypt
FUNCS += functions/gnutls_cipher_decrypt2
FUNCS += functions/gnutls_cipher_encrypt2
FUNCS += functions/gnutls_cipher_set_iv
FUNCS += functions/gnutls_cipher_tag
FUNCS += functions/gnutls_cipher_add_auth
FUNCS += functions/gnutls_cipher_deinit
FUNCS += functions/gnutls_cipher_get_block_size
FUNCS += functions/gnutls_hmac_init
FUNCS += functions/gnutls_hmac
FUNCS += functions/gnutls_hmac_output
FUNCS += functions/gnutls_hmac_deinit
FUNCS += functions/gnutls_hmac_get_len
FUNCS += functions/gnutls_hmac_fast
FUNCS += functions/gnutls_hash_init
FUNCS += functions/gnutls_hash
FUNCS += functions/gnutls_hash_output
FUNCS += functions/gnutls_hash_deinit
FUNCS += functions/gnutls_hash_get_len
FUNCS += functions/gnutls_hash_fast
FUNCS += functions/gnutls_rnd
FUNCS += functions/gnutls_dtls_set_timeouts
FUNCS += functions/gnutls_dtls_get_mtu
FUNCS += functions/gnutls_dtls_get_data_mtu
FUNCS += functions/gnutls_dtls_set_mtu
FUNCS += functions/gnutls_dtls_set_data_mtu
FUNCS += functions/gnutls_dtls_get_timeout
FUNCS += functions/gnutls_dtls_cookie_send
FUNCS += functions/gnutls_dtls_cookie_verify
FUNCS += functions/gnutls_dtls_prestate_set
FUNCS += functions/gnutls_record_get_discarded
FUNCS += functions/gnutls_pk_algorithm_get_name
FUNCS += functions/gnutls_init
FUNCS += functions/gnutls_deinit
FUNCS += functions/gnutls_bye
FUNCS += functions/gnutls_handshake
FUNCS += functions/gnutls_rehandshake
FUNCS += functions/gnutls_alert_get
FUNCS += functions/gnutls_alert_send
FUNCS += functions/gnutls_alert_send_appropriate
FUNCS += functions/gnutls_alert_get_name
FUNCS += functions/gnutls_alert_get_strname
FUNCS += functions/gnutls_pk_bits_to_sec_param
FUNCS += functions/gnutls_sec_param_get_name
FUNCS += functions/gnutls_sec_param_to_pk_bits
FUNCS += functions/gnutls_ecc_curve_get_name
FUNCS += functions/gnutls_ecc_curve_get_size
FUNCS += functions/gnutls_ecc_curve_get
FUNCS += functions/gnutls_cipher_get
FUNCS += functions/gnutls_kx_get
FUNCS += functions/gnutls_mac_get
FUNCS += functions/gnutls_compression_get
FUNCS += functions/gnutls_certificate_type_get
FUNCS += functions/gnutls_sign_algorithm_get_requested
FUNCS += functions/gnutls_cipher_get_key_size
FUNCS += functions/gnutls_mac_get_key_size
FUNCS += functions/gnutls_cipher_get_name
FUNCS += functions/gnutls_mac_get_name
FUNCS += functions/gnutls_compression_get_name
FUNCS += functions/gnutls_kx_get_name
FUNCS += functions/gnutls_certificate_type_get_name
FUNCS += functions/gnutls_pk_get_name
FUNCS += functions/gnutls_sign_get_name
FUNCS += functions/gnutls_pk_to_sign
FUNCS += functions/gnutls_mac_get_id
FUNCS += functions/gnutls_compression_get_id
FUNCS += functions/gnutls_cipher_get_id
FUNCS += functions/gnutls_kx_get_id
FUNCS += functions/gnutls_protocol_get_id
FUNCS += functions/gnutls_certificate_type_get_id
FUNCS += functions/gnutls_pk_get_id
FUNCS += functions/gnutls_sign_get_id
FUNCS += functions/gnutls_ecc_curve_list
FUNCS += functions/gnutls_cipher_list
FUNCS += functions/gnutls_mac_list
FUNCS += functions/gnutls_compression_list
FUNCS += functions/gnutls_protocol_list
FUNCS += functions/gnutls_certificate_type_list
FUNCS += functions/gnutls_kx_list
FUNCS += functions/gnutls_pk_list
FUNCS += functions/gnutls_sign_list
FUNCS += functions/gnutls_cipher_suite_info
FUNCS += functions/gnutls_error_is_fatal
FUNCS += functions/gnutls_error_to_alert
FUNCS += functions/gnutls_perror
FUNCS += functions/gnutls_strerror
FUNCS += functions/gnutls_strerror_name
FUNCS += functions/gnutls_handshake_set_private_extensions
FUNCS += functions/gnutls_handshake_get_last_out
FUNCS += functions/gnutls_handshake_get_last_in
FUNCS += functions/gnutls_record_send
FUNCS += functions/gnutls_record_recv
FUNCS += functions/gnutls_record_recv_seq
FUNCS += functions/gnutls_session_enable_compatibility_mode
FUNCS += functions/gnutls_record_disable_padding
FUNCS += functions/gnutls_record_get_direction
FUNCS += functions/gnutls_record_get_max_size
FUNCS += functions/gnutls_record_set_max_size
FUNCS += functions/gnutls_record_check_pending
FUNCS += functions/gnutls_prf
FUNCS += functions/gnutls_prf_raw
FUNCS += functions/gnutls_server_name_set
FUNCS += functions/gnutls_server_name_get
FUNCS += functions/gnutls_safe_renegotiation_status
FUNCS += functions/gnutls_supplemental_get_name
FUNCS += functions/gnutls_session_ticket_key_generate
FUNCS += functions/gnutls_session_ticket_enable_client
FUNCS += functions/gnutls_session_ticket_enable_server
FUNCS += functions/gnutls_key_generate
FUNCS += functions/gnutls_priority_init
FUNCS += functions/gnutls_priority_deinit
FUNCS += functions/gnutls_priority_get_cipher_suite_index
FUNCS += functions/gnutls_priority_set
FUNCS += functions/gnutls_priority_set_direct
FUNCS += functions/gnutls_priority_certificate_type_list
FUNCS += functions/gnutls_priority_sign_list
FUNCS += functions/gnutls_priority_protocol_list
FUNCS += functions/gnutls_priority_compression_list
FUNCS += functions/gnutls_priority_ecc_curve_list
FUNCS += functions/gnutls_set_default_priority
FUNCS += functions/gnutls_cipher_suite_get_name
FUNCS += functions/gnutls_protocol_get_version
FUNCS += functions/gnutls_protocol_get_name
FUNCS += functions/gnutls_session_set_data
FUNCS += functions/gnutls_session_get_data
FUNCS += functions/gnutls_session_get_data2
FUNCS += functions/gnutls_session_get_random
FUNCS += functions/gnutls_session_set_premaster
FUNCS += functions/gnutls_session_get_id
FUNCS += functions/gnutls_session_channel_binding
FUNCS += functions/gnutls_session_is_resumed
FUNCS += functions/gnutls_session_resumption_requested
FUNCS += functions/gnutls_db_set_cache_expiration
FUNCS += functions/gnutls_db_remove_session
FUNCS += functions/gnutls_db_set_retrieve_function
FUNCS += functions/gnutls_db_set_remove_function
FUNCS += functions/gnutls_db_set_store_function
FUNCS += functions/gnutls_db_set_ptr
FUNCS += functions/gnutls_db_get_ptr
FUNCS += functions/gnutls_db_check_entry
FUNCS += functions/gnutls_handshake_set_post_client_hello_function
FUNCS += functions/gnutls_handshake_set_max_packet_length
FUNCS += functions/gnutls_check_version
FUNCS += functions/gnutls_credentials_clear
FUNCS += functions/gnutls_credentials_set
FUNCS += functions/gnutls_anon_free_server_credentials
FUNCS += functions/gnutls_anon_allocate_server_credentials
FUNCS += functions/gnutls_anon_set_server_dh_params
FUNCS += functions/gnutls_anon_set_server_params_function
FUNCS += functions/gnutls_anon_free_client_credentials
FUNCS += functions/gnutls_anon_allocate_client_credentials
FUNCS += functions/gnutls_certificate_free_credentials
FUNCS += functions/gnutls_certificate_allocate_credentials
FUNCS += functions/gnutls_certificate_get_issuer
FUNCS += functions/gnutls_certificate_free_keys
FUNCS += functions/gnutls_certificate_free_cas
FUNCS += functions/gnutls_certificate_free_ca_names
FUNCS += functions/gnutls_certificate_free_crls
FUNCS += functions/gnutls_certificate_set_dh_params
FUNCS += functions/gnutls_certificate_set_verify_flags
FUNCS += functions/gnutls_certificate_set_verify_limits
FUNCS += functions/gnutls_certificate_set_x509_system_trust
FUNCS += functions/gnutls_certificate_set_x509_trust_file
FUNCS += functions/gnutls_certificate_set_x509_trust_mem
FUNCS += functions/gnutls_certificate_set_x509_crl_file
FUNCS += functions/gnutls_certificate_set_x509_crl_mem
FUNCS += functions/gnutls_certificate_set_x509_key_file
FUNCS += functions/gnutls_certificate_set_x509_key_mem
FUNCS += functions/gnutls_certificate_send_x509_rdn_sequence
FUNCS += functions/gnutls_certificate_set_x509_simple_pkcs12_file
FUNCS += functions/gnutls_certificate_set_x509_simple_pkcs12_mem
FUNCS += functions/gnutls_certificate_set_x509_key
FUNCS += functions/gnutls_certificate_set_x509_trust
FUNCS += functions/gnutls_certificate_set_x509_crl
FUNCS += functions/gnutls_global_init
FUNCS += functions/gnutls_global_deinit
FUNCS += functions/gnutls_global_set_mutex
FUNCS += functions/gnutls_global_set_mem_functions
FUNCS += functions/gnutls_global_set_time_function
FUNCS += functions/gnutls_global_set_log_function
FUNCS += functions/gnutls_global_set_audit_log_function
FUNCS += functions/gnutls_global_set_log_level
FUNCS += functions/gnutls_dh_params_init
FUNCS += functions/gnutls_dh_params_deinit
FUNCS += functions/gnutls_dh_params_import_raw
FUNCS += functions/gnutls_dh_params_import_pkcs3
FUNCS += functions/gnutls_dh_params_generate2
FUNCS += functions/gnutls_dh_params_export_pkcs3
FUNCS += functions/gnutls_dh_params_export_raw
FUNCS += functions/gnutls_dh_params_cpy
FUNCS += functions/gnutls_transport_set_ptr
FUNCS += functions/gnutls_transport_set_ptr2
FUNCS += functions/gnutls_transport_get_ptr
FUNCS += functions/gnutls_transport_get_ptr2
FUNCS += functions/gnutls_transport_set_vec_push_function
FUNCS += functions/gnutls_transport_set_push_function
FUNCS += functions/gnutls_transport_set_pull_function
FUNCS += functions/gnutls_transport_set_pull_timeout_function
FUNCS += functions/gnutls_transport_set_errno_function
FUNCS += functions/gnutls_transport_set_errno
FUNCS += functions/gnutls_session_set_ptr
FUNCS += functions/gnutls_session_get_ptr
FUNCS += functions/gnutls_openpgp_send_cert
FUNCS += functions/gnutls_fingerprint
FUNCS += functions/gnutls_random_art
FUNCS += functions/gnutls_srp_free_client_credentials
FUNCS += functions/gnutls_srp_allocate_client_credentials
FUNCS += functions/gnutls_srp_set_client_credentials
FUNCS += functions/gnutls_srp_free_server_credentials
FUNCS += functions/gnutls_srp_allocate_server_credentials
FUNCS += functions/gnutls_srp_set_server_credentials_file
FUNCS += functions/gnutls_srp_server_get_username
FUNCS += functions/gnutls_srp_set_prime_bits
FUNCS += functions/gnutls_srp_verifier
FUNCS += functions/gnutls_srp_set_server_credentials_function
FUNCS += functions/gnutls_srp_set_client_credentials_function
FUNCS += functions/gnutls_srp_base64_encode
FUNCS += functions/gnutls_srp_base64_encode_alloc
FUNCS += functions/gnutls_srp_base64_decode
FUNCS += functions/gnutls_srp_base64_decode_alloc
FUNCS += functions/gnutls_psk_free_client_credentials
FUNCS += functions/gnutls_psk_allocate_client_credentials
FUNCS += functions/gnutls_psk_set_client_credentials
FUNCS += functions/gnutls_psk_free_server_credentials
FUNCS += functions/gnutls_psk_allocate_server_credentials
FUNCS += functions/gnutls_psk_set_server_credentials_file
FUNCS += functions/gnutls_psk_set_server_credentials_hint
FUNCS += functions/gnutls_psk_server_get_username
FUNCS += functions/gnutls_psk_client_get_hint
FUNCS += functions/gnutls_psk_set_server_credentials_function
FUNCS += functions/gnutls_psk_set_client_credentials_function
FUNCS += functions/gnutls_hex_encode
FUNCS += functions/gnutls_hex_decode
FUNCS += functions/gnutls_psk_set_server_dh_params
FUNCS += functions/gnutls_psk_set_server_params_function
FUNCS += functions/gnutls_auth_get_type
FUNCS += functions/gnutls_auth_server_get_type
FUNCS += functions/gnutls_auth_client_get_type
FUNCS += functions/gnutls_dh_set_prime_bits
FUNCS += functions/gnutls_dh_get_secret_bits
FUNCS += functions/gnutls_dh_get_peers_public_bits
FUNCS += functions/gnutls_dh_get_prime_bits
FUNCS += functions/gnutls_dh_get_group
FUNCS += functions/gnutls_dh_get_pubkey
FUNCS += functions/gnutls_certificate_set_retrieve_function
FUNCS += functions/gnutls_certificate_set_verify_function
FUNCS += functions/gnutls_certificate_server_set_request
FUNCS += functions/gnutls_certificate_get_peers
FUNCS += functions/gnutls_certificate_get_ours
FUNCS += functions/gnutls_certificate_activation_time_peers
FUNCS += functions/gnutls_certificate_expiration_time_peers
FUNCS += functions/gnutls_certificate_client_get_request_status
FUNCS += functions/gnutls_certificate_verify_peers2
FUNCS += functions/gnutls_pem_base64_encode
FUNCS += functions/gnutls_pem_base64_decode
FUNCS += functions/gnutls_pem_base64_encode_alloc
FUNCS += functions/gnutls_pem_base64_decode_alloc
FUNCS += functions/gnutls_certificate_set_params_function
FUNCS += functions/gnutls_anon_set_params_function
FUNCS += functions/gnutls_psk_set_params_function
FUNCS += functions/gnutls_hex2bin
FUNCS += functions/gnutls_tdb_init
FUNCS += functions/gnutls_tdb_set_store_func
FUNCS += functions/gnutls_tdb_set_store_commitment_func
FUNCS += functions/gnutls_tdb_set_verify_func
FUNCS += functions/gnutls_tdb_deinit
FUNCS += functions/gnutls_verify_stored_pubkey
FUNCS += functions/gnutls_store_commitment
FUNCS += functions/gnutls_store_pubkey
FUNCS += functions/gnutls_ocsp_req_init
FUNCS += functions/gnutls_ocsp_req_deinit
FUNCS += functions/gnutls_ocsp_req_import
FUNCS += functions/gnutls_ocsp_req_export
FUNCS += functions/gnutls_ocsp_req_print
FUNCS += functions/gnutls_ocsp_req_get_version
FUNCS += functions/gnutls_ocsp_req_get_cert_id
FUNCS += functions/gnutls_ocsp_req_add_cert_id
FUNCS += functions/gnutls_ocsp_req_add_cert
FUNCS += functions/gnutls_ocsp_req_get_extension
FUNCS += functions/gnutls_ocsp_req_set_extension
FUNCS += functions/gnutls_ocsp_req_get_nonce
FUNCS += functions/gnutls_ocsp_req_set_nonce
FUNCS += functions/gnutls_ocsp_req_randomize_nonce
FUNCS += functions/gnutls_ocsp_resp_init
FUNCS += functions/gnutls_ocsp_resp_deinit
FUNCS += functions/gnutls_ocsp_resp_import
FUNCS += functions/gnutls_ocsp_resp_export
FUNCS += functions/gnutls_ocsp_resp_print
FUNCS += functions/gnutls_ocsp_resp_get_status
FUNCS += functions/gnutls_ocsp_resp_get_response
FUNCS += functions/gnutls_ocsp_resp_get_version
FUNCS += functions/gnutls_ocsp_resp_get_responder
FUNCS += functions/gnutls_ocsp_resp_get_produced
FUNCS += functions/gnutls_ocsp_resp_get_single
FUNCS += functions/gnutls_ocsp_resp_get_extension
FUNCS += functions/gnutls_ocsp_resp_get_nonce
FUNCS += functions/gnutls_ocsp_resp_get_signature_algorithm
FUNCS += functions/gnutls_ocsp_resp_get_signature
FUNCS += functions/gnutls_ocsp_resp_get_certs
FUNCS += functions/gnutls_ocsp_resp_verify_direct
FUNCS += functions/gnutls_ocsp_resp_verify
FUNCS += functions/gnutls_openpgp_crt_init
FUNCS += functions/gnutls_openpgp_crt_deinit
FUNCS += functions/gnutls_openpgp_crt_import
FUNCS += functions/gnutls_openpgp_crt_export
FUNCS += functions/gnutls_openpgp_crt_print
FUNCS += functions/gnutls_openpgp_crt_get_key_usage
FUNCS += functions/gnutls_openpgp_crt_get_fingerprint
FUNCS += functions/gnutls_openpgp_crt_get_subkey_fingerprint
FUNCS += functions/gnutls_openpgp_crt_get_name
FUNCS += functions/gnutls_openpgp_crt_get_pk_algorithm
FUNCS += functions/gnutls_openpgp_crt_get_version
FUNCS += functions/gnutls_openpgp_crt_get_creation_time
FUNCS += functions/gnutls_openpgp_crt_get_expiration_time
FUNCS += functions/gnutls_openpgp_crt_get_key_id
FUNCS += functions/gnutls_openpgp_crt_check_hostname
FUNCS += functions/gnutls_openpgp_crt_get_revoked_status
FUNCS += functions/gnutls_openpgp_crt_get_subkey_count
FUNCS += functions/gnutls_openpgp_crt_get_subkey_idx
FUNCS += functions/gnutls_openpgp_crt_get_subkey_revoked_status
FUNCS += functions/gnutls_openpgp_crt_get_subkey_pk_algorithm
FUNCS += functions/gnutls_openpgp_crt_get_subkey_creation_time
FUNCS += functions/gnutls_openpgp_crt_get_subkey_expiration_time
FUNCS += functions/gnutls_openpgp_crt_get_subkey_id
FUNCS += functions/gnutls_openpgp_crt_get_subkey_usage
FUNCS += functions/gnutls_openpgp_crt_get_subkey_pk_dsa_raw
FUNCS += functions/gnutls_openpgp_crt_get_subkey_pk_rsa_raw
FUNCS += functions/gnutls_openpgp_crt_get_pk_dsa_raw
FUNCS += functions/gnutls_openpgp_crt_get_pk_rsa_raw
FUNCS += functions/gnutls_openpgp_crt_get_preferred_key_id
FUNCS += functions/gnutls_openpgp_crt_set_preferred_key_id
FUNCS += functions/gnutls_openpgp_privkey_init
FUNCS += functions/gnutls_openpgp_privkey_deinit
FUNCS += functions/gnutls_openpgp_privkey_get_pk_algorithm
FUNCS += functions/gnutls_openpgp_privkey_sec_param
FUNCS += functions/gnutls_openpgp_privkey_import
FUNCS += functions/gnutls_openpgp_privkey_get_fingerprint
FUNCS += functions/gnutls_openpgp_privkey_get_subkey_fingerprint
FUNCS += functions/gnutls_openpgp_privkey_get_key_id
FUNCS += functions/gnutls_openpgp_privkey_get_subkey_count
FUNCS += functions/gnutls_openpgp_privkey_get_subkey_idx
FUNCS += functions/gnutls_openpgp_privkey_get_subkey_revoked_status
FUNCS += functions/gnutls_openpgp_privkey_get_revoked_status
FUNCS += functions/gnutls_openpgp_privkey_get_subkey_pk_algorithm
FUNCS += functions/gnutls_openpgp_privkey_get_subkey_id
FUNCS += functions/gnutls_openpgp_privkey_get_subkey_creation_time
FUNCS += functions/gnutls_openpgp_privkey_export_subkey_dsa_raw
FUNCS += functions/gnutls_openpgp_privkey_export_subkey_rsa_raw
FUNCS += functions/gnutls_openpgp_privkey_export_dsa_raw
FUNCS += functions/gnutls_openpgp_privkey_export_rsa_raw
FUNCS += functions/gnutls_openpgp_privkey_export
FUNCS += functions/gnutls_openpgp_privkey_set_preferred_key_id
FUNCS += functions/gnutls_openpgp_privkey_get_preferred_key_id
FUNCS += functions/gnutls_openpgp_crt_get_auth_subkey
FUNCS += functions/gnutls_openpgp_keyring_init
FUNCS += functions/gnutls_openpgp_keyring_deinit
FUNCS += functions/gnutls_openpgp_keyring_import
FUNCS += functions/gnutls_openpgp_keyring_check_id
FUNCS += functions/gnutls_openpgp_crt_verify_ring
FUNCS += functions/gnutls_openpgp_crt_verify_self
FUNCS += functions/gnutls_openpgp_keyring_get_crt
FUNCS += functions/gnutls_openpgp_keyring_get_crt_count
FUNCS += functions/gnutls_openpgp_set_recv_key_function
FUNCS += functions/gnutls_certificate_set_openpgp_key
FUNCS += functions/gnutls_certificate_set_openpgp_key_file
FUNCS += functions/gnutls_certificate_set_openpgp_key_mem
FUNCS += functions/gnutls_certificate_set_openpgp_key_file2
FUNCS += functions/gnutls_certificate_set_openpgp_key_mem2
FUNCS += functions/gnutls_certificate_set_openpgp_keyring_mem
FUNCS += functions/gnutls_certificate_set_openpgp_keyring_file
FUNCS += functions/gnutls_pkcs11_init
FUNCS += functions/gnutls_pkcs11_reinit
FUNCS += functions/gnutls_pkcs11_deinit
FUNCS += functions/gnutls_pkcs11_set_token_function
FUNCS += functions/gnutls_pkcs11_set_pin_function
FUNCS += functions/gnutls_pkcs11_add_provider
FUNCS += functions/gnutls_pkcs11_obj_init
FUNCS += functions/gnutls_pkcs11_obj_import_url
FUNCS += functions/gnutls_pkcs11_obj_export_url
FUNCS += functions/gnutls_pkcs11_obj_deinit
FUNCS += functions/gnutls_pkcs11_obj_export
FUNCS += functions/gnutls_pkcs11_copy_x509_crt
FUNCS += functions/gnutls_pkcs11_copy_x509_privkey
FUNCS += functions/gnutls_pkcs11_delete_url
FUNCS += functions/gnutls_pkcs11_copy_secret_key
FUNCS += functions/gnutls_pkcs11_obj_get_info
FUNCS += functions/gnutls_pkcs11_token_init
FUNCS += functions/gnutls_pkcs11_token_get_mechanism
FUNCS += functions/gnutls_pkcs11_token_set_pin
FUNCS += functions/gnutls_pkcs11_token_get_url
FUNCS += functions/gnutls_pkcs11_token_get_info
FUNCS += functions/gnutls_pkcs11_token_get_flags
FUNCS += functions/gnutls_pkcs11_obj_list_import_url
FUNCS += functions/gnutls_x509_crt_import_pkcs11
FUNCS += functions/gnutls_x509_crt_import_pkcs11_url
FUNCS += functions/gnutls_pkcs11_obj_get_type
FUNCS += functions/gnutls_pkcs11_type_get_name
FUNCS += functions/gnutls_x509_crt_list_import_pkcs11
FUNCS += functions/gnutls_pkcs11_privkey_init
FUNCS += functions/gnutls_pkcs11_privkey_deinit
FUNCS += functions/gnutls_pkcs11_privkey_get_pk_algorithm
FUNCS += functions/gnutls_pkcs11_privkey_get_info
FUNCS += functions/gnutls_pkcs11_privkey_import_url
FUNCS += functions/gnutls_pkcs11_privkey_export_url
FUNCS += functions/gnutls_pkcs11_privkey_generate
FUNCS += functions/gnutls_pkcs12_init
FUNCS += functions/gnutls_pkcs12_deinit
FUNCS += functions/gnutls_pkcs12_import
FUNCS += functions/gnutls_pkcs12_export
FUNCS += functions/gnutls_pkcs12_get_bag
FUNCS += functions/gnutls_pkcs12_set_bag
FUNCS += functions/gnutls_pkcs12_generate_mac
FUNCS += functions/gnutls_pkcs12_verify_mac
FUNCS += functions/gnutls_pkcs12_bag_decrypt
FUNCS += functions/gnutls_pkcs12_bag_encrypt
FUNCS += functions/gnutls_pkcs12_bag_get_type
FUNCS += functions/gnutls_pkcs12_bag_get_data
FUNCS += functions/gnutls_pkcs12_bag_set_data
FUNCS += functions/gnutls_pkcs12_bag_set_crl
FUNCS += functions/gnutls_pkcs12_bag_set_crt
FUNCS += functions/gnutls_pkcs12_bag_init
FUNCS += functions/gnutls_pkcs12_bag_deinit
FUNCS += functions/gnutls_pkcs12_bag_get_count
FUNCS += functions/gnutls_pkcs12_bag_get_key_id
FUNCS += functions/gnutls_pkcs12_bag_set_key_id
FUNCS += functions/gnutls_pkcs12_bag_get_friendly_name
FUNCS += functions/gnutls_pkcs12_bag_set_friendly_name
FUNCS += functions/gnutls_x509_crt_init
FUNCS += functions/gnutls_x509_crt_deinit
FUNCS += functions/gnutls_x509_crt_import
FUNCS += functions/gnutls_x509_crt_list_import2
FUNCS += functions/gnutls_x509_crt_list_import
FUNCS += functions/gnutls_x509_crt_export
FUNCS += functions/gnutls_x509_crt_get_private_key_usage_period
FUNCS += functions/gnutls_x509_crt_get_issuer_dn
FUNCS += functions/gnutls_x509_crt_get_issuer_dn_oid
FUNCS += functions/gnutls_x509_crt_get_issuer_dn_by_oid
FUNCS += functions/gnutls_x509_crt_get_dn
FUNCS += functions/gnutls_x509_crt_get_dn_oid
FUNCS += functions/gnutls_x509_crt_get_dn_by_oid
FUNCS += functions/gnutls_x509_crt_check_hostname
FUNCS += functions/gnutls_x509_crt_get_signature_algorithm
FUNCS += functions/gnutls_x509_crt_get_signature
FUNCS += functions/gnutls_x509_crt_get_version
FUNCS += functions/gnutls_x509_crt_get_key_id
FUNCS += functions/gnutls_x509_crt_set_private_key_usage_period
FUNCS += functions/gnutls_x509_crt_set_authority_key_id
FUNCS += functions/gnutls_x509_crt_get_authority_key_id
FUNCS += functions/gnutls_x509_crt_get_authority_key_gn_serial
FUNCS += functions/gnutls_x509_crt_get_subject_key_id
FUNCS += functions/gnutls_x509_crt_get_subject_unique_id
FUNCS += functions/gnutls_x509_crt_get_issuer_unique_id
FUNCS += functions/gnutls_x509_crt_get_authority_info_access
FUNCS += functions/gnutls_x509_crt_get_crl_dist_points
FUNCS += functions/gnutls_x509_crt_set_crl_dist_points2
FUNCS += functions/gnutls_x509_crt_set_crl_dist_points
FUNCS += functions/gnutls_x509_crt_cpy_crl_dist_points
FUNCS += functions/gnutls_x509_crl_sign2
FUNCS += functions/gnutls_x509_crt_get_activation_time
FUNCS += functions/gnutls_x509_crt_get_expiration_time
FUNCS += functions/gnutls_x509_crt_get_serial
FUNCS += functions/gnutls_x509_crt_get_pk_algorithm
FUNCS += functions/gnutls_x509_crt_get_pk_rsa_raw
FUNCS += functions/gnutls_x509_crt_get_pk_dsa_raw
FUNCS += functions/gnutls_x509_crt_get_subject_alt_name
FUNCS += functions/gnutls_x509_crt_get_subject_alt_name2
FUNCS += functions/gnutls_x509_crt_get_subject_alt_othername_oid
FUNCS += functions/gnutls_x509_crt_get_issuer_alt_name
FUNCS += functions/gnutls_x509_crt_get_issuer_alt_name2
FUNCS += functions/gnutls_x509_crt_get_issuer_alt_othername_oid
FUNCS += functions/gnutls_x509_crt_get_ca_status
FUNCS += functions/gnutls_x509_crt_get_basic_constraints
FUNCS += functions/gnutls_x509_crt_get_key_usage
FUNCS += functions/gnutls_x509_crt_set_key_usage
FUNCS += functions/gnutls_x509_crt_set_authority_info_access
FUNCS += functions/gnutls_x509_crt_get_proxy
FUNCS += functions/gnutls_x509_dn_oid_known
FUNCS += functions/gnutls_x509_dn_oid_name
FUNCS += functions/gnutls_x509_crt_get_extension_oid
FUNCS += functions/gnutls_x509_crt_get_extension_by_oid
FUNCS += functions/gnutls_x509_crt_get_extension_info
FUNCS += functions/gnutls_x509_crt_get_extension_data
FUNCS += functions/gnutls_x509_crt_set_extension_by_oid
FUNCS += functions/gnutls_x509_crt_set_dn_by_oid
FUNCS += functions/gnutls_x509_crt_set_issuer_dn_by_oid
FUNCS += functions/gnutls_x509_crt_set_version
FUNCS += functions/gnutls_x509_crt_set_key
FUNCS += functions/gnutls_x509_crt_set_ca_status
FUNCS += functions/gnutls_x509_crt_set_basic_constraints
FUNCS += functions/gnutls_x509_crt_set_subject_alternative_name
FUNCS += functions/gnutls_x509_crt_set_subject_alt_name
FUNCS += functions/gnutls_x509_crt_sign
FUNCS += functions/gnutls_x509_crt_sign2
FUNCS += functions/gnutls_x509_crt_set_activation_time
FUNCS += functions/gnutls_x509_crt_set_expiration_time
FUNCS += functions/gnutls_x509_crt_set_serial
FUNCS += functions/gnutls_x509_crt_set_subject_key_id
FUNCS += functions/gnutls_x509_crt_set_proxy_dn
FUNCS += functions/gnutls_x509_crt_set_proxy
FUNCS += functions/gnutls_x509_crt_print
FUNCS += functions/gnutls_x509_crl_print
FUNCS += functions/gnutls_x509_crt_get_raw_issuer_dn
FUNCS += functions/gnutls_x509_crt_get_raw_dn
FUNCS += functions/gnutls_x509_rdn_get
FUNCS += functions/gnutls_x509_rdn_get_oid
FUNCS += functions/gnutls_x509_rdn_get_by_oid
FUNCS += functions/gnutls_x509_crt_get_subject
FUNCS += functions/gnutls_x509_crt_get_issuer
FUNCS += functions/gnutls_x509_dn_get_rdn_ava
FUNCS += functions/gnutls_x509_dn_init
FUNCS += functions/gnutls_x509_dn_import
FUNCS += functions/gnutls_x509_dn_export
FUNCS += functions/gnutls_x509_dn_deinit
FUNCS += functions/gnutls_x509_crl_init
FUNCS += functions/gnutls_x509_crl_deinit
FUNCS += functions/gnutls_x509_crl_import
FUNCS += functions/gnutls_x509_crl_export
FUNCS += functions/gnutls_x509_crl_get_raw_issuer_dn
FUNCS += functions/gnutls_x509_crl_get_issuer_dn
FUNCS += functions/gnutls_x509_crl_get_issuer_dn_by_oid
FUNCS += functions/gnutls_x509_crl_get_dn_oid
FUNCS += functions/gnutls_x509_crl_get_signature_algorithm
FUNCS += functions/gnutls_x509_crl_get_signature
FUNCS += functions/gnutls_x509_crl_get_version
FUNCS += functions/gnutls_x509_crl_get_this_update
FUNCS += functions/gnutls_x509_crl_get_next_update
FUNCS += functions/gnutls_x509_crl_get_crt_count
FUNCS += functions/gnutls_x509_crl_get_crt_serial
FUNCS += functions/gnutls_x509_crl_check_issuer
FUNCS += functions/gnutls_x509_crl_list_import2
FUNCS += functions/gnutls_x509_crl_list_import
FUNCS += functions/gnutls_x509_crl_set_version
FUNCS += functions/gnutls_x509_crl_set_this_update
FUNCS += functions/gnutls_x509_crl_set_next_update
FUNCS += functions/gnutls_x509_crl_set_crt_serial
FUNCS += functions/gnutls_x509_crl_set_crt
FUNCS += functions/gnutls_x509_crl_get_authority_key_id
FUNCS += functions/gnutls_x509_crl_get_authority_key_gn_serial
FUNCS += functions/gnutls_x509_crl_get_number
FUNCS += functions/gnutls_x509_crl_get_extension_oid
FUNCS += functions/gnutls_x509_crl_get_extension_info
FUNCS += functions/gnutls_x509_crl_get_extension_data
FUNCS += functions/gnutls_x509_crl_set_authority_key_id
FUNCS += functions/gnutls_x509_crl_set_number
FUNCS += functions/gnutls_pkcs7_init
FUNCS += functions/gnutls_pkcs7_deinit
FUNCS += functions/gnutls_pkcs7_import
FUNCS += functions/gnutls_pkcs7_export
FUNCS += functions/gnutls_pkcs7_get_crt_count
FUNCS += functions/gnutls_pkcs7_get_crt_raw
FUNCS += functions/gnutls_pkcs7_set_crt_raw
FUNCS += functions/gnutls_pkcs7_set_crt
FUNCS += functions/gnutls_pkcs7_delete_crt
FUNCS += functions/gnutls_pkcs7_get_crl_raw
FUNCS += functions/gnutls_pkcs7_get_crl_count
FUNCS += functions/gnutls_pkcs7_set_crl_raw
FUNCS += functions/gnutls_pkcs7_set_crl
FUNCS += functions/gnutls_pkcs7_delete_crl
FUNCS += functions/gnutls_x509_crt_check_issuer
FUNCS += functions/gnutls_x509_crt_list_verify
FUNCS += functions/gnutls_x509_crt_verify
FUNCS += functions/gnutls_x509_crl_verify
FUNCS += functions/gnutls_x509_crt_check_revocation
FUNCS += functions/gnutls_x509_crt_get_fingerprint
FUNCS += functions/gnutls_x509_crt_get_key_purpose_oid
FUNCS += functions/gnutls_x509_crt_set_key_purpose_oid
FUNCS += functions/gnutls_x509_privkey_init
FUNCS += functions/gnutls_x509_privkey_deinit
FUNCS += functions/gnutls_x509_privkey_sec_param
FUNCS += functions/gnutls_x509_privkey_cpy
FUNCS += functions/gnutls_x509_privkey_import
FUNCS += functions/gnutls_x509_privkey_import_pkcs8
FUNCS += functions/gnutls_x509_privkey_import_rsa_raw
FUNCS += functions/gnutls_x509_privkey_import_rsa_raw2
FUNCS += functions/gnutls_x509_privkey_import_ecc_raw
FUNCS += functions/gnutls_x509_privkey_fix
FUNCS += functions/gnutls_x509_privkey_export_dsa_raw
FUNCS += functions/gnutls_x509_privkey_import_dsa_raw
FUNCS += functions/gnutls_x509_privkey_get_pk_algorithm
FUNCS += functions/gnutls_x509_privkey_get_key_id
FUNCS += functions/gnutls_x509_privkey_generate
FUNCS += functions/gnutls_x509_privkey_verify_params
FUNCS += functions/gnutls_x509_privkey_export
FUNCS += functions/gnutls_x509_privkey_export_pkcs8
FUNCS += functions/gnutls_x509_privkey_export_rsa_raw2
FUNCS += functions/gnutls_x509_privkey_export_rsa_raw
FUNCS += functions/gnutls_x509_privkey_export_ecc_raw
FUNCS += functions/gnutls_x509_crq_sign2
FUNCS += functions/gnutls_x509_crq_print
FUNCS += functions/gnutls_x509_crq_verify
FUNCS += functions/gnutls_x509_crq_init
FUNCS += functions/gnutls_x509_crq_deinit
FUNCS += functions/gnutls_x509_crq_import
FUNCS += functions/gnutls_x509_crq_get_private_key_usage_period
FUNCS += functions/gnutls_x509_crq_get_dn
FUNCS += functions/gnutls_x509_crq_get_dn_oid
FUNCS += functions/gnutls_x509_crq_get_dn_by_oid
FUNCS += functions/gnutls_x509_crq_set_dn_by_oid
FUNCS += functions/gnutls_x509_crq_set_version
FUNCS += functions/gnutls_x509_crq_get_version
FUNCS += functions/gnutls_x509_crq_set_key
FUNCS += functions/gnutls_x509_crq_set_challenge_password
FUNCS += functions/gnutls_x509_crq_get_challenge_password
FUNCS += functions/gnutls_x509_crq_set_attribute_by_oid
FUNCS += functions/gnutls_x509_crq_get_attribute_by_oid
FUNCS += functions/gnutls_x509_crq_export
FUNCS += functions/gnutls_x509_crt_set_crq
FUNCS += functions/gnutls_x509_crt_set_crq_extensions
FUNCS += functions/gnutls_x509_crq_set_private_key_usage_period
FUNCS += functions/gnutls_x509_crq_set_key_rsa_raw
FUNCS += functions/gnutls_x509_crq_set_subject_alt_name
FUNCS += functions/gnutls_x509_crq_set_key_usage
FUNCS += functions/gnutls_x509_crq_set_basic_constraints
FUNCS += functions/gnutls_x509_crq_set_key_purpose_oid
FUNCS += functions/gnutls_x509_crq_get_key_purpose_oid
FUNCS += functions/gnutls_x509_crq_get_extension_data
FUNCS += functions/gnutls_x509_crq_get_extension_info
FUNCS += functions/gnutls_x509_crq_get_attribute_data
FUNCS += functions/gnutls_x509_crq_get_attribute_info
FUNCS += functions/gnutls_x509_crq_get_pk_algorithm
FUNCS += functions/gnutls_x509_crq_get_key_id
FUNCS += functions/gnutls_x509_crq_get_key_rsa_raw
FUNCS += functions/gnutls_x509_crq_get_key_usage
FUNCS += functions/gnutls_x509_crq_get_basic_constraints
FUNCS += functions/gnutls_x509_crq_get_subject_alt_name
FUNCS += functions/gnutls_x509_crq_get_subject_alt_othername_oid
FUNCS += functions/gnutls_x509_crq_get_extension_by_oid
FUNCS += functions/gnutls_x509_trust_list_init
FUNCS += functions/gnutls_x509_trust_list_deinit
FUNCS += functions/gnutls_x509_trust_list_get_issuer
FUNCS += functions/gnutls_x509_trust_list_add_cas
FUNCS += functions/gnutls_x509_trust_list_add_named_crt
FUNCS += functions/gnutls_x509_trust_list_add_crls
FUNCS += functions/gnutls_x509_trust_list_verify_named_crt
FUNCS += functions/gnutls_x509_trust_list_verify_crt
