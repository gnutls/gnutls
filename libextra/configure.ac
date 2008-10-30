dnl Process this file with autoconf to produce a configure script.
# Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008
#    Free Software Foundation, Inc.
#
# Author: Nikos Mavrogiannopoulos, Simon Josefsson
#
# This file is part of GNUTLS-EXTRA.
#
# GNUTLS-EXTRA is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
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

AC_PREREQ(2.61)
AC_INIT([libgnutls-extra], [2.7.1], [bug-gnutls@gnu.org])
AC_CONFIG_AUX_DIR([../build-aux])
AC_CONFIG_MACRO_DIR([../m4])

AM_INIT_AUTOMAKE([1.10 -Wall -Werror -Wno-override])
AM_CONFIG_HEADER(config.h)

AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL

AC_MSG_CHECKING([whether to disable OpenSSL compatibility layer])
AC_ARG_ENABLE(openssl-compatibility,
	AS_HELP_STRING([--disable-openssl-compatibility],
		[disable the OpenSSL compatibility support]),
	ac_enable_openssl=$withval,
	ac_enable_openssl=yes)
if test x$ac_enable_openssl != xno; then
 AC_MSG_RESULT(no)
else
 AC_MSG_RESULT(yes)
fi
AM_CONDITIONAL(ENABLE_OPENSSL, test "$ac_enable_openssl" = "yes")

# Check for libtasn1
AC_ARG_WITH(included-libtasn1,
  AS_HELP_STRING([--with-included-libtasn1], [use the included libtasn1]),
    included_libtasn1=$withval,
    included_libtasn1=no)
if test "$included_libtasn1" = "no"; then
  AC_LIB_HAVE_LINKFLAGS(tasn1,, [#include <libtasn1.h>],
  				[asn1_check_version (NULL)])
  if test "$ac_cv_libtasn1" != yes; then
    included_libtasn1=yes
    AC_MSG_WARN([[
*** 
*** Libtasn1 was not found. Will use the included one.
]])
  fi
fi
AC_MSG_CHECKING([whether to use the included minitasn1])
AC_MSG_RESULT($included_libtasn1)
AM_CONDITIONAL(ENABLE_MINITASN1, test "$included_libtasn1" = "yes")

AC_CONFIG_FILES([ \
  libextra/Makefile \
  libextra/gl/Makefile \
  libextra/gnutls-extra.pc \
])
AC_OUTPUT
