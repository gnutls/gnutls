## Process this file with automake to produce Makefile.in
# Copyright © 2026 David Dudas
# 
# Author: David Dudas <david.dudas03@e-uvt.ro>
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
# 
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>

include $(top_srcdir)/lib/common.mk

AM_CPPFLAGS += \
	-I$(srcdir)/../../gl		\
	-I$(builddir)/../../gl		\
	-I$(srcdir)/../includes		\
	-I$(builddir)/../includes	\
	-I$(builddir)/../../gl          \
	-I$(srcdir)/..

noinst_LTLIBRARIES = libgnutls_hpke.la

libgnutls_hpke_la_SOURCES = \
	hpke.c \
	hpke-builders.c \
	hpke-hkdf.c \
	hpke-key-management.c \
	hpke-params.c
