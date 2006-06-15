# arpa_inet_h.m4 serial 1
dnl Copyright (C) 2006 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl From Simon Josefsson.

AC_DEFUN([gl_HEADER_ARPA_INET],
[
  # Do we need to create the arpa/inet.h file?
  AC_CHECK_HEADERS_ONCE([arpa/inet.h])
  if test $ac_cv_header_arpa_inet_h = yes; then
    ARPA_INET_H=''
  else
    dnl We cannot use AC_CHECK_HEADERS_ONCE here, because that would make
    dnl the check for those headers unconditional; yet cygwin reports
    dnl that the headers are present but cannot be compiled (since on
    dnl cygwin, all socket information should come from sys/socket.h).
    AC_CHECK_HEADERS([ws2tcpip.h])
    ARPA_INET_H='arpa/inet.h'
    gl_PREREQ_ARPA_INET
  fi
  AC_SUBST(ARPA_INET_H)

  # Do we need to provide our own inet_ntop and inet_pton too?
  AC_REPLACE_FUNCS(inet_ntop)
  AC_REPLACE_FUNCS(inet_pton)
  if test $ac_cv_func_inet_ntop = no -o $ac_cv_func_inet_pton = no; then
    gl_PREREQ_INET_NTOP
  fi
])

# Prerequisites of arpa/inet.h.
AC_DEFUN([gl_PREREQ_ARPA_INET], [
  AC_CHECK_DECLS([inet_ntop, inet_pton],,,[
#include <sys/types.h>
#include <sys/socket.h>])
])

# Prerequisites of lib/inet_ntop.c and lib/inet_pton.c.
AC_DEFUN([gl_PREREQ_INET_NTOP], [
  AC_REQUIRE([gl_SOCKET_FAMILIES])
])
