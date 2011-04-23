## Process this file with automake to produce Makefile.in
# Copyright (C) 2011 Free Software
# Foundation, Inc.
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
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with the GNUTLS library; if not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA

AM_LIBTOOLFLAGS=--tag=CC
AM_CFLAGS = $(WERROR_CFLAGS) $(WSTACK_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = \
	-I$(srcdir)/../../../gl		\
	-I$(srcdir)/../../includes	\
	-I$(srcdir)/../../ \
	-I$(srcdir)/../

if ENABLE_MINITASN1
AM_CPPFLAGS += -I$(srcdir)/../../minitasn1
endif

EXTRA_DIST = aes-x86.h README license.txt

noinst_LTLIBRARIES = libintel.la

libintel_la_SOURCES = aes-x86.c
libintel_la_LIBADD =

if ASM_X86_64
libintel_la_SOURCES += asm/appro-aes-x86-64.s
else
libintel_la_SOURCES += asm/appro-aes-x86.s
endif

