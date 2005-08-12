# isascii.m4 serial 1
dnl Copyright (C) 2005 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_FUNC_ISASCII],
[
  AC_LIBSOURCES([isascii.h, isascii.c])

  dnl Persuade glibc <ctype.h> to declare isascii().
  AC_REQUIRE([AC_GNU_SOURCE])
 
  AC_REPLACE_FUNCS(isascii)
  AC_CHECK_DECLS_ONCE(isascii)
])

# Prerequisites of lib/isascii.h.
AC_DEFUN([gl_PREREQ_ISASCII], [:])
