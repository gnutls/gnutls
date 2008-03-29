## Process this file with automake to produce Makefile.in
# Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008 Free Software Foundation
#
# Author: Nikos Mavroyanopoulos
#
# This file is part of GNUTLS.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

nobase_include_HEADERS = gnutls/extra.h gnutls/x509.h gnutls/pkcs12.h	\
	gnutls/compat.h gnutls/openpgp.h gnutls/crypto.h

if ENABLE_OPENSSL
nobase_include_HEADERS += gnutls/openssl.h
endif

if ENABLE_CXX
nobase_include_HEADERS += gnutls/gnutlsxx.h
endif

nobase_nodist_include_HEADERS = gnutls/gnutls.h
