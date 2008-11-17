# output-def.m4 serial 1
dnl Copyright (C) 2008 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl From Simon Josefsson

# sj_OUTPUT_DEF()
# -------------
# Check if linker supports -Wl,--output-def and define automake
# conditional HAVE_LD_OUTPUT_DEF if it is.
AC_DEFUN([sj_OUTPUT_DEF],
[
  AC_MSG_CHECKING([if gcc/ld supports -Wl,--output-def])
  if test "$enable_shared" = no; then
    output_def=no
    AC_MSG_RESULT([no need, since shared libraries are disabled])
  else
    _gcc_ldflags_save=$LDFLAGS
    LDFLAGS="-Wl,--output-def,foo.def"
    AC_LINK_IFELSE(AC_LANG_PROGRAM([]),output_def=yes,output_def=no)
    rm -f foo.def
    AC_MSG_RESULT($output_def)
    LDFLAGS="$_gcc_ldflags_save"
  fi
  AM_CONDITIONAL(HAVE_LD_OUTPUT_DEF, test "$output_def" = "yes")
])
