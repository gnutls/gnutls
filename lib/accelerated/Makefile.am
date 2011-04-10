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

AM_CFLAGS = $(WERROR_CFLAGS) $(WSTACK_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = \
	-I$(srcdir)/../../gl		\
	-I$(srcdir)/../includes		\
	-I$(builddir)/../includes	\
	-I$(srcdir)/..

noinst_LTLIBRARIES = libaccelerated.la

EXTRA_DIST = x86.h aes-x86.h accelerated.h
libaccelerated_la_SOURCES = accelerated.c

if TRY_X86_OPTIMIZATIONS
AM_CFLAGS += -DTRY_X86_OPTIMIZATIONS
libaccelerated_la_SOURCES += aes-x86.c
endif

