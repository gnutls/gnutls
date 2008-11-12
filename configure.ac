dnl Process this file with autoconf to produce a configure script.
# Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008
#    Free Software Foundation, Inc.
#
# Author: Nikos Mavrogiannopoulos, Simon Josefsson
#
# This file is part of GNUTLS.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
# USA

AC_PREREQ(2.61)
AC_INIT([GnuTLS], [2.7.2], [bug-gnutls@gnu.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.10 dist-bzip2 -Wall -Werror -Wno-override])
AM_CONFIG_HEADER(config.h)

AC_MSG_RESULT([***
*** Checking for compilation programs...
])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_LN_S
GTK_DOC_CHECK(1.1)
AC_PATH_PROG([GAA], [gaa])
if test "x$GAA" = "x"; then
   AC_MSG_WARN([[***
*** GAA was not found.  It is only needed if you wish to modify
*** the source code or command-line description files.  In this case,
*** you may want to get it from http://gaa.sourceforge.net/
***]])
fi
AM_CONDITIONAL(HAVE_GCC,   test "x$GCC" = "xyes")

gl_EARLY
AC_C_INLINE

LIBGNUTLS_HOOKS
LIBGNUTLS_EXTRA_HOOKS

AC_MSG_CHECKING([whether gcc supports -fgnu89-inline])
_gcc_cflags_save="$CFLAGS"
CFLAGS="${CFLAGS} -fgnu89-inline"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
                  _gcc_gnu89_inline=yes, _gcc_gnu89_inline=no)
AC_MSG_RESULT($_gcc_gnu89_inline)
CFLAGS="$_gcc_cflags_save"
AM_CONDITIONAL([HAVE_GCC_GNU89_INLINE_OPTION],
               [test "$_gcc_gnu89_inline" = "yes"])

AC_HEADER_STDC
AC_CHECK_FUNCS(fork,,)
AC_DEFINE([HAVE_STRINGS_H], 1, [Hard-code for src/cfg/.])
AC_DEFINE([HAVE_FLOAT_H], 1, [Hard-code for src/cfg/.])
AC_DEFINE([HAVE_LIMITS_H], 1, [Hard-code for src/cfg/.])
AC_DEFINE([HAVE_MATH_H], 1, [Hard-code for src/cfg/.])
AC_DEFINE([HAVE_CTYPE_H], 1, [Hard-code for src/cfg/.])
AC_DEFINE([HAVE_ERRNO_H], 1, [Hard-code for src/cfg/.])

# No fork on MinGW, disable some self-tests until we fix them.
AM_CONDITIONAL(HAVE_FORK, test "$ac_cv_func_fork" != "no")

sj_VALGRIND

AC_CHECK_TYPES(uint,,, [
# include <sys/types.h>
])

# For Guile bindings.
opt_guile_bindings=yes
AC_MSG_CHECKING([whether building Guile bindings])
AC_ARG_ENABLE(guile,
	AS_HELP_STRING([--enable-guile], [build GNU Guile bindings]),
opt_guile_bindings=$enableval)
AC_MSG_RESULT($opt_guile_bindings)

AC_ARG_WITH([--with-guile-site-dir],
  [AS_HELP_STRING([--with-guile-site-dir],
     [use the given directory as the Guile site (use with care)])])

if test "x$opt_guile_bindings" = "xyes"; then
   AC_MSG_RESULT([***
*** Detecting GNU Guile...
])

   AC_PATH_PROG([guile_snarf], [guile-snarf])
   if test "x$guile_snarf" = "x"; then
      AC_MSG_WARN([`guile-snarf' from Guile 1.8 not found.  Guile bindings not built.])
      opt_guile_bindings=no
   else
      GUILE_PROGS
      GUILE_FLAGS

      save_CFLAGS="$CFLAGS"
      save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $GUILE_CFLAGS"
      LIBS="$LIBS $GUILE_LDFLAGS"
      AC_MSG_CHECKING([whether GNU Guile is recent enough])
      AC_LINK_IFELSE(AC_LANG_CALL([], [scm_from_locale_string]),
        [], [opt_guile_bindings=no])
      CFLAGS="$save_CFLAGS"
      LIBS="$save_LIBS"

      if test "x$opt_guile_bindings" = "xyes"; then
        AC_MSG_RESULT([yes])
	case "x$with_guile_site_dir" in 
	     xno)
		# Use the default $(GUILE_SITE).
		GUILE_SITE_DIR
		;;
	     x|xyes)
		# Automatically derive $(GUILE_SITE) from $(pkgdatadir).  This
		# hack is used to allow `distcheck' to work (see
		# `DISTCHECK_CONFIGURE_FLAGS' in the top-level `Makefile.am').
		GUILE_SITE="\$(datadir)/guile/site"
		AC_SUBST(GUILE_SITE)
		;;
	     *)
		# Use the user-specified directory as $(GUILE_SITE).
		GUILE_SITE="$with_guile_site_dir"
		AC_SUBST(GUILE_SITE)
		;;
	esac
      else
        AC_MSG_RESULT([no])
        AC_MSG_WARN([A sufficiently recent GNU Guile not found.  Guile bindings not built.])
        opt_guile_bindings=no
      fi
   fi
fi
AM_CONDITIONAL(HAVE_GUILE, test "x$opt_guile_bindings" = "xyes")

dnl Check for libcfg+

SAVED_LIBS=$LIBS
AC_ARG_WITH(included-libcfg,
	AS_HELP_STRING([--with-included-libcfg],
		[use the included libcfg+ (certtool only)]),
	libcfg_enabled=$withval, 
	libcfg_enabled=no
dnl We search for libcfg+ which is used by certtool
dnl
	AC_CHECK_LIB(cfg+, cfg_get_context,:,
                     libcfg_enabled=yes
                     AC_MSG_WARN([[
*** 
*** Libcfg+ was not found. Will use the included one.]])))

AM_CONDITIONAL(HAVE_LIBCFG, test "$libcfg_enabled" = "no")
LIBS=$SAVED_LIBS

AC_MSG_CHECKING([whether to use the included libcfg])
AC_MSG_RESULT($libcfg_enabled)

AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL

gl_INIT

# These are warnings we could enable:
# -W -Wchar-subscripts -Wformat-security -Wnonnull -Winit-self -Wmissing-include-dirs -Wunused -Wno-unused-parameter -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wunsafe-loop-optimizations -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align -Wlogical-op -Waggregate-return -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn -Wmissing-format-attribute -Wpacked -Wredundant-decls -Wnested-externs -Winline -Wvla -Wvolatile-register-var -Wdisabled-optimization -Wstack-protector -Woverlength-strings -Wno-pointer-sign
#
# These are warnings we have tried but have turned out not to be useful:
#
# -Wtraditional: warns on #elif which we use often
# -Wundef: warns on '#if GNULIB_PORTCHECK' etc in gnulib headers
# -Wpadded: many of our structs are not optimized for padding
# -Wtraditional-conversion: we catch missing prototypes anyway
# -Wno-unused-parameter: added because -Wunused cause too many warns
# -Wunreachable-code: appears to return many false positives
# -Wconversion: too many warnings for now
# -Wswitch-default: too many warnings for now
# -Wswitch-enum: too many warnings for now

for w in -Wall; do
  gl_WARN_ADD([$w])
done
export WARN_CFLAGS

AC_CONFIG_SUBDIRS([lib])
AC_CONFIG_SUBDIRS([libextra])

AC_CONFIG_FILES([guile/pre-inst-guile], [chmod +x guile/pre-inst-guile])
AC_CONFIG_FILES([
  Makefile
  doc/Makefile
  doc/credentials/Makefile
  doc/credentials/openpgp/Makefile
  doc/credentials/srp/Makefile
  doc/credentials/x509/Makefile
  doc/cyclo/Makefile
  doc/doxygen/Doxyfile
  doc/examples/Makefile
  doc/manpages/Makefile
  doc/reference/Makefile
  doc/scripts/Makefile
  gl/Makefile
  gl/tests/Makefile
  guile/Makefile
  guile/modules/Makefile
  guile/src/Makefile
  guile/tests/Makefile
  src/Makefile
  src/cfg/Makefile
  src/cfg/platon/Makefile
  src/cfg/platon/str/Makefile
  tests/Makefile
  tests/key-id/Makefile
  tests/openpgp-certs/Makefile
  tests/pathlen/Makefile
  tests/pkcs1-padding/Makefile
  tests/pkcs12-decode/Makefile
  tests/pkcs8-decode/Makefile
  tests/rsa-md5-collision/Makefile
  tests/sha2/Makefile
  tests/userid/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([summary of build options:

  version:          ${VERSION} shared $LT_CURRENT:$LT_REVISION:$LT_AGE
  Host type:        ${host}
  Install prefix:   ${prefix}
  Compiler:         ${CC}
  Warning flags:    ${WARN_CFLAGS}
  Library types:    Shared=${enable_shared}, Static=${enable_static}
  Valgrind:         ${VALGRIND}
  Linker script:    $have_ld_version_script
])
