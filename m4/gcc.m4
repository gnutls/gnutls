# gcc.m4 serial 2
dnl Copyright (C) 2008-2012 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl Based on code by Simon Josefsson

# GCC_FLAG_ADD(PARAMETER, [ACTION])
# ------------------------------------------------
# Adds parameter to CFLAGS if the compiler supports it.  For example,
# GCC_FLAG_ADD([-maes], [VAR]).
AC_DEFUN([GCC_FLAG_ADD],
[AS_VAR_PUSHDEF([GCC_FLAG], [gl_cv_GCC_FLAG_$1])dnl
AC_CACHE_CHECK([whether compiler handles $1], [GCC_FLAG], [
  save_CFLAGS="$CFLAGS"
  CFLAGS="${CFLAGS} $1"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
                    [AS_VAR_SET([GCC_FLAG], [yes])],
                    [AS_VAR_SET([GCC_FLAG], [no])])
  CFLAGS="$save_CFLAGS"
])
AS_VAR_IF([GCC_FLAG], [yes], [
m4_ifval([$2], [AC_SUBST([$2],[yes])])
CFLAGS="${CFLAGS} $1"
])dnl
AS_VAR_POPDEF([GCC_FLAG])
])
