dnl Process this file with autoconf to produce a configure script.
# Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008
#    Free Software Foundation, Inc.
#
# Author: Nikos Mavrogiannopoulos, Simon Josefsson
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

AC_PREREQ(2.61)
AC_INIT([libgnutls], [2.7.1], [bug-gnutls@gnu.org])
AC_CONFIG_AUX_DIR([../build-aux])
AC_CONFIG_MACRO_DIR([../m4])

AM_INIT_AUTOMAKE([1.10 -Wall -Werror -Wno-override])
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AC_PROG_CXX
lgl_EARLY

AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL

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

AC_MSG_CHECKING([whether to enable Opaque PRF input support])
AC_ARG_ENABLE(opaque-prf-input,
	AS_HELP_STRING([--enable-opaque-prf-input=DD],
		[enable Opaque PRF input using DD as extension type]),
	ac_opaque_prf_input=$enableval, ac_opaque_prf_input=no)
if test "$ac_opaque_prf_input" != "no"; then
  if ! echo $ac_opaque_prf_input | egrep -q '^[[0-9]]+$'; then
    ac_opaque_prf_input=no
    AC_MSG_WARN([[
*** Could not parse Opaque PRF Input extension type.
*** Use --enable-opaque-prf-input=XX where XX is decimal, for example
*** to use extension value 42 use --enable-opqaue-prf-input=42]])
  fi
fi
if test "$ac_opaque_prf_input" != "no"; then
 AC_MSG_RESULT([yes (extension value $ac_opaque_prf_input)])
 AC_DEFINE_UNQUOTED(ENABLE_OPRFI, $ac_opaque_prf_input,
                    [enable Opaque PRF Input])
else
 AC_MSG_RESULT(no)
fi
AM_CONDITIONAL(ENABLE_OPRFI, test "$ac_opaque_prf_input" != "no")

AC_MSG_CHECKING([whether to disable SRP authentication support])
AC_ARG_ENABLE(srp-authentication,
	AS_HELP_STRING([--disable-srp-authentication],
		[disable the SRP authentication support]),
	ac_enable_srp=no)
if test x$ac_enable_srp != xno; then
 AC_MSG_RESULT(no)
 AC_DEFINE(ENABLE_SRP, 1, [enable SRP authentication])
else
 ac_full=0
 AC_MSG_RESULT(yes)
fi
AM_CONDITIONAL(ENABLE_SRP, test "$ac_enable_srp" != "no")

AC_MSG_CHECKING([whether to disable PSK authentication support])
AC_ARG_ENABLE(psk-authentication,
       AS_HELP_STRING([--disable-psk-authentication],
               [disable the PSK authentication support]),
       ac_enable_psk=no)
if test x$ac_enable_psk != xno; then
 AC_MSG_RESULT(no)
 AC_DEFINE(ENABLE_PSK, 1, [enable PSK authentication])
else
 ac_full=0
 AC_MSG_RESULT(yes)
fi
AM_CONDITIONAL(ENABLE_PSK, test "$ac_enable_psk" != "no")

AC_MSG_CHECKING([whether to disable anonymous authentication support])
AC_ARG_ENABLE(anon-authentication,
	AS_HELP_STRING([--disable-anon-authentication],
		[disable the anonymous authentication support]),
	ac_enable_anon=no)
if test x$ac_enable_anon != xno; then
 AC_MSG_RESULT(no)
 AC_DEFINE(ENABLE_ANON, 1, [enable anonymous authentication])
else
 ac_full=0
 AC_MSG_RESULT(yes)
fi
AM_CONDITIONAL(ENABLE_ANON, test "$ac_enable_anon" != "no")

# Allow disabling Camellia
AC_ARG_ENABLE(camellia,
  AS_HELP_STRING([--disable-camellia], [disable Camellia cipher]),
  enable_camellia=$enableval, enable_camellia=no)
AC_MSG_CHECKING([whether to disable Camellia cipher])
if test "$enable_camellia" != "no"; then
 AC_MSG_RESULT([no])
 AC_DEFINE(ENABLE_CAMELLIA, 1, [enable camellia block cipher])
else
 AC_MSG_RESULT([yes])
fi

AC_MSG_CHECKING([whether to disable extra PKI stuff])
AC_ARG_ENABLE(extra-pki,
	AS_HELP_STRING([--disable-extra-pki],
		[only enable the basic PKI stuff]),
	enable_pki=$enableval, enable_pki=yes)
if test "$enable_pki" != "yes"; then
 ac_full=0
 AC_MSG_RESULT(yes)
else
 AC_MSG_RESULT(no)
 AC_DEFINE(ENABLE_PKI, 1, [whether to include all the PKCS/PKI stuff])
fi
AM_CONDITIONAL(ENABLE_PKI, test "$enable_pki" = "yes")

ac_enable_openpgp=yes
AC_MSG_CHECKING([whether to disable OpenPGP Certificate authentication support])
AC_ARG_ENABLE(openpgp-authentication,
	AS_HELP_STRING([--disable-openpgp-authentication],
		[disable the OpenPGP authentication support]),
	ac_enable_openpgp=no)
if test x$ac_enable_openpgp = xno; then
 AC_MSG_RESULT(yes)
 ac_full=0
else
 AC_DEFINE(ENABLE_OPENPGP, 1, [use openpgp authentication])
 AC_MSG_RESULT(no)
fi
AM_CONDITIONAL(ENABLE_OPENPGP, test "$ac_enable_openpgp" = "yes")

dnl CHECK FOR ZLIB SUPPORT
dnl

AC_MSG_CHECKING([whether to include zlib compression support])

AC_ARG_WITH(zlib,
	AS_HELP_STRING([--without-zlib], [disable zlib compression support]),
	ac_zlib=$withval,
	ac_zlib=yes)

if test x$ac_zlib != xno; then
 AC_MSG_RESULT(yes)
 AC_LIB_HAVE_LINKFLAGS(z,, [#include <zlib.h>], [compress (0, 0, 0, 0);])
 if test "$ac_cv_libz" != yes; then
   AC_MSG_WARN(
*** 
*** ZLIB was not found. You will not be able to use ZLIB compression.)
 fi
else
 AC_MSG_RESULT(no)
fi

lgl_INIT

LIBGNUTLS_LIBS="-L${libdir} -lgnutls $LIBS"
LIBGNUTLS_CFLAGS="-I${includedir}"
AC_SUBST(LIBGNUTLS_LIBS)
AC_SUBST(LIBGNUTLS_CFLAGS)

AC_CONFIG_FILES([ \
  Makefile \
  minitasn1/Makefile \
  x509/Makefile \
  openpgp/Makefile \
  opencdk/Makefile \
  gnutls.pc \
])
AC_OUTPUT
