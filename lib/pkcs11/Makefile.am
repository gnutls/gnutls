## Process this file with automake to produce Makefile.in
# Copyright (C) 2025 Red Hat, Inc.
#
# Author: Zoltan Fridrich
#
# This file is part of GnuTLS.
#
# The GnuTLS is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>

include $(top_srcdir)/lib/common.mk

AM_CPPFLAGS += \
	-I$(srcdir)/../../gl		\
	-I$(builddir)/../../gl		\
	-I$(srcdir)/../includes		\
	-I$(builddir)/../includes	\
	-I$(srcdir)/..			\
	$(LIBTASN1_CFLAGS)		\
	$(P11_KIT_CFLAGS)

if ENABLE_MINITASN1
AM_CPPFLAGS += -I$(srcdir)/../minitasn1
endif

noinst_LTLIBRARIES = libgnutls_pkcs11.la

libgnutls_pkcs11_la_SOURCES = \
	p11_provider.c p11_provider.h

libgnutls_pkcs11_la_LIBADD = $(P11_KIT_LIBS) $(LIBPMULTITHREAD)

if ENABLE_MINITASN1
libgnutls_pkcs11_la_LIBADD += ../minitasn1/libminitasn1.la
else
libgnutls_pkcs11_la_LIBADD += $(LIBTASN1_LIBS)
endif
