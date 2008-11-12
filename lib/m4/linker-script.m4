# linker-script.m4 serial 1
dnl Copyright (C) 2008 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl From Simon Josefsson

# sj_LINKER_SCRIPT(VERSION-SCRIPT)
# -------------
# Check if ld supports linker scripts, and define automake conditional
# HAVE_LD_VERSION_SCRIPT if so.  VERSION-SCRIPT is a valid version script
# file.
AC_DEFUN([sj_LINKER_SCRIPT],
[
  AC_ARG_ENABLE([ld-version-script],
    AS_HELP_STRING([--enable-ld-version-script],
      [enable/disable linker version script (default is enabled when possible)]),
      [have_ld_version_script=$enableval], [])
  if test -z "$have_ld_version_script"; then
    AC_MSG_CHECKING([if -Wl,--version-script works])
    save_LDFLAGS="$LDFLAGS"
    LDFLAGS="$LDFLAGS -Wl,--version-script=$1"
    AC_LINK_IFELSE(AC_LANG_PROGRAM([], []),
                   [have_ld_version_script=yes], [have_ld_version_script=no])
    LDFLAGS="$save_LDFLAGS"
    AC_MSG_RESULT($have_ld_version_script)
  fi
  AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")
])
