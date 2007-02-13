## Process this file with automake to produce Makefile.in
# Copyright (C) 2004, 2005, 2006, 2007 Free Software Foundation
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

INCLUDES = -I$(top_srcdir)/lib \
	-I$(top_srcdir)/lgl -I$(top_builddir)/lgl

noinst_LTLIBRARIES = libminiopencdk.la

libminiopencdk_la_SOURCES = md.h packet.h opencdk.h context.h main.h	\
        cipher.h stream.h types.h filters.h new-packet.c read-packet.c	\
        write-packet.c main.c verify.c armor.c sig-check.c sign.c	\
        keydb.c keylist.c seskey.c pubkey.c misc.c encrypt.c trustdb.c	\
        kbnode.c compress.c plaintext.c cipher.c sym-cipher.c stream.c	\
        keyserver.c keygen.c md.c

EXTRA_DIST = README
