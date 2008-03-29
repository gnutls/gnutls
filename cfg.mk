# Copyright (C) 2006, 2007, 2008 Free Software Foundation
#
# Author: Simon Josefsson
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

CFGFLAGS ?= --enable-developer-mode --enable-gtk-doc

INDENT_SOURCES = `ls includes/gnutls/*.h{,.in} {lib,lib/x509,libextra,libextra/openpgp,src,tests}/*.{c,h} | grep -v -- -gaa`

ifeq ($(.DEFAULT_GOAL),abort-due-to-no-makefile)
.DEFAULT_GOAL := bootstrap
endif

autoreconf:
	mv build-aux/config.rpath build-aux/config.rpath-
	test -f ./configure || autoreconf --install
	mv build-aux/config.rpath- build-aux/config.rpath

bootstrap: autoreconf
	./configure $(CFGFLAGS)

LIBGCRYPTROOT ?= $(HOME)/w32root

mingw32: autoreconf 
	./configure $(CFGFLAGS) --host=i586-mingw32msvc --build=`./config.guess` --with-included-libtasn1 --with-included-opencdk --with-libgcrypt-prefix=$(LIBGCRYPTROOT)

.PHONY: bootstrap autoreconf mingw32
