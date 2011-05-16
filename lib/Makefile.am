## Process this file with automake to produce Makefile.in
# Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
# 2009, 2010, 2011 Free Software Foundation, Inc.
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GnuTLS.
#
# The GnuTLS is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# The GnuTLS is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with GnuTLS; if not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA

ACLOCAL_AMFLAGS = -I ../m4 -I ../gl/m4

EXTRA_DIST = pakchois/README
SUBDIRS = includes x509 accelerated auth ext
if ENABLE_MINITASN1
SUBDIRS += minitasn1
endif

localedir = $(datadir)/locale

AM_CFLAGS = $(WERROR_CFLAGS) $(WSTACK_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = \
	-DLOCALEDIR=\"$(localedir)\"		\
	-I$(srcdir)/../gl				\
	-I$(srcdir)/includes			\
	-I$(srcdir)/x509

if ENABLE_OPENPGP
SUBDIRS += opencdk
SUBDIRS += openpgp
AM_CPPFLAGS += -I$(srcdir)/opencdk
endif

if ENABLE_MINITASN1
AM_CPPFLAGS += -I$(srcdir)/minitasn1
endif

# Pkg-config script.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gnutls.pc
DISTCLEANFILES = $(pkgconfig_DATA)

lib_LTLIBRARIES = libgnutls.la

SRP_COBJECTS = gnutls_srp.c

PSK_COBJECTS = gnutls_psk.c

COBJECTS = gnutls_record.c gnutls_compress.c debug.c gnutls_cipher.c	\
	gnutls_mbuffers.c gnutls_buffers.c gnutls_handshake.c gnutls_num.c \
	gnutls_errors.c gnutls_algorithms.c gnutls_dh.c gnutls_kx.c	\
	gnutls_priority.c gnutls_hash_int.c gnutls_cipher_int.c		\
	gnutls_session.c gnutls_db.c x509_b64.c 		\
	gnutls_extensions.c gnutls_auth.c gnutls_v2_compat.c		\
	gnutls_datum.c gnutls_session_pack.c gnutls_mpi.c	\
	gnutls_pk.c gnutls_cert.c gnutls_global.c gnutls_constate.c	\
	gnutls_anon_cred.c pkix_asn1_tab.c gnutls_asn1_tab.c		\
	gnutls_mem.c gnutls_ui.c gnutls_sig.c gnutls_ecc.c		\
	gnutls_dh_primes.c gnutls_alert.c system.c		\
	gnutls_str.c gnutls_state.c gnutls_x509.c gnutls_rsa_export.c  	\
	gnutls_helper.c gnutls_supplemental.c crypto.c random.c  \
	crypto-api.c gnutls_privkey.c gnutls_pcert.c \
	pkcs11.c pkcs11_privkey.c gnutls_pubkey.c pkcs11_write.c locks.c \
	pkcs11_secret.c hash.c gnutls_dtls.c system_override.c


if ENABLE_NETTLE
SUBDIRS += nettle
else
SUBDIRS += gcrypt
endif

HFILES = abstract_int.h debug.h gnutls_compress.h gnutls_cipher.h	\
	gnutls_buffers.h gnutls_errors.h gnutls_int.h gnutls_dtls.h	\
	gnutls_handshake.h gnutls_num.h gnutls_algorithms.h		\
	gnutls_dh.h gnutls_kx.h gnutls_hash_int.h gnutls_cipher_int.h	\
	gnutls_db.h gnutls_auth.h gnutls_extensions.h	\
	x509_b64.h gnutls_v2_compat.h gnutls_datum.h \
	gnutls_mpi.h gnutls_pk.h gnutls_record.h		\
	gnutls_constate.h gnutls_global.h gnutls_sig.h gnutls_mem.h	\
	gnutls_session_pack.h gnutls_str.h		\
	gnutls_state.h gnutls_x509.h 			\
	gnutls_rsa_export.h gnutls_srp.h auth/srp.h auth/srp_passwd.h	\
	gnutls_helper.h gnutls_supplemental.h crypto.h random.h system.h\
	locks.h gnutls_mbuffers.h pkcs11_int.h \
	hash.h

COBJECTS+=pakchois/pakchois.c pakchois/errors.c pakchois/dlopen.c
HFILES+=pakchois/pakchois.h pakchois/pakchois11.h pakchois/dlopen.h

# Separate so we can create the documentation

libgnutls_la_SOURCES = $(HFILES) $(COBJECTS) $(SRP_COBJECTS)	\
	$(PSK_COBJECTS) \
	gnutls.asn pkix.asn libgnutls.map

libgnutls_la_LDFLAGS = -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

libgnutls_la_LIBADD = ../gl/libgnu.la x509/libgnutls_x509.la \
	accelerated/libaccelerated.la ext/libgnutls_ext.la \
	auth/libgnutls_auth.la \
	$(LTLIBZ)  $(LTLIBINTL) $(LIBSOCKET) $(LTLIBDL) \
	$(LTLIBPTHREAD)

if ENABLE_OPENPGP
libgnutls_la_LIBADD += openpgp/libgnutls_openpgp.la
libgnutls_la_LIBADD += opencdk/libminiopencdk.la
endif

if HAVE_LD_VERSION_SCRIPT
libgnutls_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libgnutls.map
else
libgnutls_la_LDFLAGS += -export-symbols-regex '^(gnutls|_gnutls).*'
endif

if ENABLE_MINITASN1
libgnutls_la_LIBADD += minitasn1/libminitasn1.la
else
libgnutls_la_LDFLAGS += $(LTLIBTASN1)
endif

if ENABLE_NETTLE
libgnutls_la_LDFLAGS += $(LTLIBNETTLE) $(NETTLE_LIBS)
libgnutls_la_LIBADD += nettle/libcrypto.la
else
libgnutls_la_LDFLAGS += $(LTLIBGCRYPT)
libgnutls_la_LIBADD += gcrypt/libcrypto.la
endif

if HAVE_LD_OUTPUT_DEF
libgnutls_la_LDFLAGS += -Wl,--output-def,libgnutls-$(DLL_VERSION).def
defexecdir = $(bindir)
defexec_DATA = libgnutls-$(DLL_VERSION).def
DISTCLEANFILES += $(defexec_DATA)
endif

# C++ library

if ENABLE_CXX
libgnutlsxx_la_CPPFLAGS = -I$(top_srcdir)/includes -I$(top_builddir)/includes

AM_CXXFLAGS = -I$(srcdir)/includes

lib_LTLIBRARIES += libgnutlsxx.la

libgnutlsxx_la_SOURCES = gnutlsxx.cpp libgnutlsxx.map

libgnutlsxx_la_LDFLAGS = -no-undefined \
	-version-info $(CXX_LT_CURRENT):$(CXX_LT_REVISION):$(CXX_LT_AGE)

libgnutlsxx_la_LIBADD = libgnutls.la

if HAVE_LD_VERSION_SCRIPT
libgnutlsxx_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libgnutlsxx.map
endif
endif

pkix_asn1_tab.c: pkix.asn
	-asn1Parser pkix.asn pkix_asn1_tab.c

gnutls_asn1_tab.c: gnutls.asn
	-asn1Parser gnutls.asn gnutls_asn1_tab.c
