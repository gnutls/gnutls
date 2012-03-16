## Process this file with automake to produce Makefile.in
# Copyright (C) 2011-2012 Free Software Foundation, Inc.
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GNUTLS.
#
# The GNUTLS library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 3 of
# the License, or (at your option) any later version.
#
# The GNUTLS library is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

AM_LIBTOOLFLAGS=--tag=CC
AM_CFLAGS = $(WERROR_CFLAGS) $(WSTACK_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = -I$(srcdir)/../../../gl		\
	-I$(builddir)/../../../gl		\
	-I$(srcdir)/../../includes	\
	-I$(builddir)/../../includes	\
	-I$(srcdir)/../../ \
	-I$(srcdir)/../

if ENABLE_MINITASN1
AM_CPPFLAGS += -I$(srcdir)/../../minitasn1
endif

EXTRA_DIST = README license.txt

noinst_LTLIBRARIES = libx86.la

libx86_la_SOURCES = sha-padlock.c hmac-padlock.c aes-x86.c aes-padlock.c aes-gcm-padlock.c aes-padlock.h aes-x86.h x86.h sha-padlock.h

if ASM_X86_64
AM_CFLAGS += -DASM_X86_64 -DASM_X86
libx86_la_SOURCES += aes-gcm-x86.c

if WINDOWS
libx86_la_SOURCES += coff/appro-aes-x86-64-coff.s coff/padlock-x86-64-coff.s coff/cpuid-x86-64-coff.s coff/appro-aes-gcm-x86-64-coff.s
endif

if MACOSX
libx86_la_SOURCES += macosx/appro-aes-x86-64-macosx.s macosx/padlock-x86-64-macosx.s macosx/cpuid-x86-64-macosx.s macosx/appro-aes-gcm-x86-64-macosx.s
endif

if ELF
libx86_la_SOURCES += elf/appro-aes-x86-64.s elf/appro-aes-gcm-x86-64.s elf/padlock-x86-64.s elf/cpuid-x86-64.s
endif

else #ASM_X86_64
AM_CFLAGS += -DASM_X86_32 -DASM_X86

if WINDOWS
libx86_la_SOURCES += coff/appro-aes-x86-coff.s coff/padlock-x86-coff.s coff/cpuid-x86-coff.s
endif

if MACOSX
libx86_la_SOURCES += macosx/appro-aes-x86-macosx.s macosx/padlock-x86-macosx.s macosx/cpuid-x86-macosx.s
endif

if ELF
libx86_la_SOURCES += elf/appro-aes-x86.s elf/padlock-x86.s elf/cpuid-x86.s
endif

endif #ASM_X86_64
