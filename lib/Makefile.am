## Process this file with automake to produce Makefile.in
# Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007 Free Software Foundation
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GNUTLS.
#
# The GNUTLS library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# The GNUTLS library is distributed in the hope that it will be
#useful, but WITHOUT ANY WARRANTY; without even the implied warranty
#of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with the GNUTLS library; if not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA

SUBDIRS = x509
if ENABLE_MINITASN1
SUBDIRS += minitasn1
endif


localedir = $(datadir)/locale

AM_CPPFLAGS = -DLOCALEDIR=\"$(localedir)\"				\
	-I$(top_srcdir)/lgl -I$(top_builddir)/lgl			\
	-I$(top_srcdir)/includes -I../includes				\
	-I$(srcdir)/x509						\
	-I$(top_srcdir)/libextra -I$(top_srcdir)/lib/openpgp/	\
	-I$(top_srcdir)/lib/opencdk 				\
	$(LIBOPENCDK_CFLAGS) $(LIBGCRYPT_CFLAGS)

if ENABLE_OPENPGP
if ENABLE_INCLUDED_OPENCDK
SUBDIRS += opencdk
AM_CPPFLAGS += -I$(srcdir)/opencdk
endif
SUBDIRS += openpgp
endif

if ENABLE_MINITASN1
AM_CPPFLAGS += -I$(srcdir)/minitasn1
else
AM_CPPFLAGS += $(LIBTASN1_CFLAGS)
endif

bin_SCRIPTS = libgnutls-config

m4datadir = $(datadir)/aclocal
dist_m4data_DATA = libgnutls.m4

# Pkg-config script.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gnutls.pc
DISTCLEANFILES = $(pkgconfig_DATA)

EXTRA_DIST = gnutls-api.texi
lib_LTLIBRARIES = libgnutls.la

SRP_COBJECTS = ext_srp.c gnutls_srp.c auth_srp.c auth_srp_passwd.c	\
	auth_srp_sb64.c auth_srp_rsa.c

PSK_COBJECTS = auth_psk.c auth_psk_passwd.c gnutls_psk.c auth_dhe_psk.c

OPRFI_COBJECTS = ext_oprfi.c

COBJECTS = gnutls_record.c gnutls_compress.c debug.c gnutls_cipher.c	\
	gnutls_buffers.c gnutls_handshake.c gnutls_num.c		\
	gnutls_errors.c gnutls_algorithms.c gnutls_dh.c gnutls_kx.c	\
	gnutls_priority.c gnutls_hash_int.c gnutls_cipher_int.c		\
	gnutls_compress_int.c gnutls_session.c gnutls_db.c x509_b64.c	\
	auth_anon.c gnutls_extensions.c gnutls_auth.c			\
	gnutls_v2_compat.c gnutls_datum.c auth_rsa.c			\
	gnutls_session_pack.c gnutls_mpi.c gnutls_pk.c gnutls_cert.c	\
	gnutls_global.c gnutls_constate.c gnutls_anon_cred.c		\
	pkix_asn1_tab.c gnutls_asn1_tab.c gnutls_mem.c auth_cert.c	\
	gnutls_ui.c gnutls_sig.c auth_dhe.c gnutls_dh_primes.c		\
	ext_max_record.c gnutls_alert.c gnutls_str.c gnutls_state.c	\
	gnutls_x509.c ext_cert_type.c gnutls_rsa_export.c		\
	auth_rsa_export.c ext_server_name.c auth_dh_common.c		\
	gnutls_helper.c ext_inner_application.c \
	gnutls_supplemental.c

if ENABLE_OPRFI
COBJECTS += $(OPRFI_COBJECTS)
endif

HFILES = debug.h gnutls_compress.h defines.h gnutls_cipher.h		\
	gnutls_buffers.h gnutls_errors.h gnutls_int.h			\
	gnutls_handshake.h gnutls_num.h gnutls_algorithms.h		\
	gnutls_dh.h gnutls_kx.h gnutls_hash_int.h gnutls_cipher_int.h	\
	gnutls_db.h gnutls_compress_int.h gnutls_session.h		\
	gnutls_auth.h auth_anon.h gnutls_extensions.h gnutls_buffer.h	\
	gnutls_auth_int.h x509_b64.h gnutls_v2_compat.h gnutls_datum.h	\
	auth_cert.h gnutls_mpi.h gnutls_pk.h gnutls_record.h		\
	gnutls_cert.h gnutls_constate.h gnutls_global.h gnutls_sig.h	\
	gnutls_mem.h io_debug.h ext_max_record.h gnutls_session_pack.h	\
	gnutls_str.h gnutls_state.h gnutls_x509.h ext_cert_type.h	\
	gnutls_rsa_export.h ext_server_name.h auth_dh_common.h		\
	ext_srp.h gnutls_srp.h auth_srp.h auth_srp_passwd.h		\
	gnutls_helper.h auth_psk.h auth_psk_passwd.h			\
	ext_inner_application.h 			\
	gnutls_supplemental.h ext_oprfi.h

# Separate so we can create the documentation

libgnutls_la_SOURCES = $(HFILES) $(COBJECTS) $(SRP_COBJECTS)	\
	$(PSK_COBJECTS) gnutls.asn pkix.asn libgnutls.vers

libgnutls_la_LDFLAGS = -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

libgnutls_la_LIBADD = ../lgl/liblgnu.la x509/libgnutls_x509.la \
	@LTLIBZ@ $(LIBGCRYPT_LIBS) @LTLIBINTL@

if ENABLE_OPENPGP
libgnutls_la_SOURCES += gnutls_openpgp.c
libgnutls_la_LIBADD += openpgp/libgnutls_openpgp.la
if ENABLE_INCLUDED_OPENCDK
libgnutls_la_LIBADD += opencdk/libminiopencdk.la
else
libgnutls_la_LDFLAGS += $(LTLIBOPENCDK) 
endif
endif

if HAVE_LD_VERSION_SCRIPT
libgnutls_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libgnutls.vers
endif

if ENABLE_MINITASN1
libgnutls_la_LIBADD += minitasn1/libminitasn1.la
else
libgnutls_la_LDFLAGS += $(LIBTASN1_LIBS) 
endif

if HAVE_LD_OUTPUT_DEF
libgnutls_la_LDFLAGS += -Wl,--output-def,libgnutls-$(SOVERSION).def
defexecdir = $(bindir)
defexec_DATA = libgnutls-$(SOVERSION).def
DISTCLEANFILES += $(defexec_DATA)
endif

# C++ library

if ENABLE_CXX
CPP_OBJECTS = gnutlsxx.cpp

AM_CXXFLAGS = -I$(top_srcdir)/includes/

lib_LTLIBRARIES += libgnutlsxx.la

libgnutlsxx_la_SOURCES = $(CPP_OBJECTS) libgnutlsxx.vers

libgnutlsxx_la_LDFLAGS = -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

libgnutlsxx_la_LIBADD = libgnutls.la

if HAVE_LD_VERSION_SCRIPT
libgnutlsxx_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libgnutlsxx.vers
endif
endif

pkix_asn1_tab.c: pkix.asn
	-asn1Parser pkix.asn pkix_asn1_tab.c

gnutls_asn1_tab.c: gnutls.asn
	-asn1Parser gnutls.asn gnutls_asn1_tab.c

gnutls-api.texi: $(COBJECTS) $(SRP_COBJECTS) $(PSK_COBJECTS) $(OPRFI_COBJECTS)
	@echo "" > gnutls-api.texi
	@for i in $(COBJECTS) $(SRP_COBJECTS) $(PSK_COBJECTS) $(OPRFI_COBJECTS); do \
		echo -n "Creating documentation for file $$i... " && \
		$(top_srcdir)/doc/scripts/gdoc -texinfo $$i >> gnutls-api.texi && \
		echo "ok"; \
	done

dist-hook: gnutls-api.texi
