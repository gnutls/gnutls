## Process this file with automake to produce Makefile.in
# Copyright (C) 2004 Simon Josefsson
#
# This file is part of GNU TLS.
#
# GNU TLS is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# GNU TLS is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with GNU TLS; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA

BUILT_SOURCES = nettle-types.h
DISTCLEANFILES = nettle-types.h

noinst_LTLIBRARIES = libnettle.la

libnettle_la_SOURCES = aes.c aes.h aes-internal.h \
		      aes-decrypt-table.c aes-decrypt.c \
		      aes-encrypt-table.c aes-encrypt.c \
		      aes-set-encrypt-key.c aes-set-decrypt-key.c aes-meta.c \
		      arcfour.c arcfour.h arcfour-crypt.c arcfour-meta.c \
		      macros.h \
		      keymap.h rotors.h parity.h \
		      cbc.c cbc.h \
		      des.c des.h desinfo.h desCode.h \
		      des3.c des-compat.c des-compat.h \
		      hmac.c hmac.h hmac-md5.c hmac-sha1.c \
		      md5.c md5.h md5-compat.c md5-compat.h md5-meta.c \
		      sha.h sha1.c sha1-compress.c sha1-meta.c \
		      nettle-meta.h \
		      nettle-internal.c nettle-internal.h \
		      memxor.h memxor.c
