## Process this file with automake to produce Makefile.in
# Copyright (C) 2005, 2006 Free Software Foundation
#
# Author: Simon Josefsson
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

AM_CPPFLAGS = -DLZO_HAVE_CONFIG_H
AM_LDFLAGS = -no-install
LDADD = libminilzo.la

noinst_LTLIBRARIES = libminilzo.la

libminilzo_la_SOURCES = lzoconf.h lzodefs.h minilzo.c minilzo.h

EXTRA_DIST = README.LZO

ctests = testmini$(EXEEXT)
TESTS = $(ctests)
check_PROGRAMS = $(ctests)
