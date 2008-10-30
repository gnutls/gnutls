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

AC_DEFUN([LIBGNUTLS_EXTRA_HOOKS],
[
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
])
