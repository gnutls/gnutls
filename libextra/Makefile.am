## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005 Free Software Foundation
#
# Author: Nikos Mavroyanopoulos
#
# This file is part of GNUTLS-EXTRA.
#
# GNUTLS-EXTRA is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# GNUTLS-EXTRA is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNUTLS-EXTRA; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

AM_CPPFLAGS = -I$(top_srcdir)/crypto -I$(top_srcdir)/gl			\
	-I$(top_srcdir)/lib -I../includes -I$(top_srcdir)/includes	\
	-I$(top_srcdir)/lib/minitasn1 -I$(srcdir)/openpgp		\
	$(LIBGCRYPT_CFLAGS)

if ENABLE_MINITASN1
AM_CPPFLAGS += -I$(top_srcdir)/lib/minitasn1
else
AM_CPPFLAGS += $(LIBTASN1_CFLAGS)
endif

SUBDIRS = 

if ENABLE_OPENPGP
if ENABLE_INCLUDED_OPENCDK
SUBDIRS += opencdk
AM_CPPFLAGS += -I$(srcdir)/opencdk
else
AM_CPPFLAGS += $(LIBOPENCDK_CFLAGS)
endif
SUBDIRS += openpgp
endif

bin_SCRIPTS = libgnutls-extra-config

m4datadir = $(datadir)/aclocal
dist_m4data_DATA = libgnutls-extra.m4

# Pkg-config script.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gnutls-extra.pc
DISTCLEANFILES = $(pkgconfig_DATA)

EXTRA_DIST = gnutls-extra-api.texi

lib_LTLIBRARIES = libgnutls-extra.la

COBJECTS = gnutls_extra.c

# OpenSSL

libgnutls_openssl_la_LDFLAGS =
if ENABLE_OPENSSL
lib_LTLIBRARIES += libgnutls-openssl.la

libgnutls_openssl_la_SOURCES = gnutls_openssl.c openssl_compat.h	\
	openssl_compat.c

libgnutls_openssl_la_LIBADD = ../lib/libgnutls.la ../crypto/libgc.la

libgnutls_openssl_la_LDFLAGS += -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

if ENABLE_MINITASN1
libgnutls_openssl_la_LIBADD += ../lib/minitasn1/libminitasn1.la
else
libgnutls_openssl_la_LDFLAGS += $(LIBTASN1_LIBS) 
endif
endif

# OpenPGP

libgnutls_extra_la_LIBADD =
libgnutls_extra_la_LDFLAGS =
if ENABLE_OPENPGP
COBJECTS += gnutls_openpgp.c
libgnutls_extra_la_LIBADD += openpgp/libgnutls_openpgp.la
if ENABLE_INCLUDED_OPENCDK
libgnutls_extra_la_LIBADD += opencdk/libminiopencdk.la
else
libgnutls_extra_la_LDFLAGS += $(LIBOPENCDK_LIBS) 
endif
endif

libgnutls_extra_la_LDFLAGS += \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	$(LZO_LIBS)

libgnutls_extra_la_SOURCES = $(COBJECTS) gnutls_extra.h

libgnutls_extra_la_LIBADD += ../lib/libgnutls.la ../gl/libgnu.la

if HAVE_LD_VERSION_SCRIPT
libgnutls_extra_la_LDFLAGS += \
	-Wl,--version-script=$(srcdir)/libgnutls-extra.vers
endif

# LZO

if ENABLE_INCLUDED_LZO
SUBDIRS += minilzo
libgnutls_extra_la_LIBADD += minilzo/libminilzo.la
endif

gnutls-extra-api.texi: $(COBJECTS)
	@echo "" > gnutls-extra-api.texi
	@for i in $(COBJECTS); do \
		echo -n "Creating documentation for file $$i... " && \
		../doc/scripts/gdoc -texinfo $$i >> gnutls-extra-api.texi && \
		echo "ok"; \
	done

dist-hook: gnutls-extra-api.texi
