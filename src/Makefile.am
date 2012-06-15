## Process this file with automake to produce Makefile.in
# Copyright (C) 2000-2012 Free Software Foundation, Inc.
#
# This file is part of GnuTLS.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

SUBDIRS =

if ENABLE_CRYWRAP
SUBDIRS += crywrap
endif

if NEED_LIBOPTS
SUBDIRS += libopts
endif

EXTRA_DIST = args-std.def

AM_CFLAGS = $(WARN_CFLAGS) $(WERROR_CFLAGS)
AM_CPPFLAGS = \
	-I$(srcdir)/../gl			\
	-I$(builddir)/../gl			\
	-I$(builddir)/../lib/includes		\
	-I$(srcdir)/../lib/includes		\
	-I$(srcdir)/../extra/includes	\
	$(LIBOPTS_CFLAGS)

bin_PROGRAMS = gnutls-serv gnutls-cli psktool gnutls-cli-debug certtool
if ENABLE_SRP
bin_PROGRAMS += srptool
endif
if ENABLE_OCSP
bin_PROGRAMS += ocsptool
endif

if ENABLE_PKCS11
bin_PROGRAMS += p11tool
PKCS11_SRCS = p11common.c p11common.h
else
PKCS11_SRCS =
endif

noinst_LTLIBRARIES =

gnutls_serv_SOURCES =		\
  list.h serv.c			\
  udp-serv.c udp-serv.h		\
  socket.c socket.h		\
  common.h common.c		\
  certtool-common.h 		\
  $(PKCS11_SRCS)
gnutls_serv_LDADD = ../lib/libgnutls.la
gnutls_serv_LDADD += libcmd-serv.la ../gl/libgnu.la $(LIBOPTS_LDADD) $(LTLIBINTL)
gnutls_serv_LDADD += $(LIBSOCKET) $(GETADDRINFO_LIB)
noinst_LTLIBRARIES += libcmd-serv.la
libcmd_serv_la_CFLAGS =
libcmd_serv_la_SOURCES = serv-args.def serv-args.c serv-args.h

if ENABLE_SRP
srptool_SOURCES = srptool.c
srptool_LDADD = ../lib/libgnutls.la libcmd-srp.la ../gl/libgnu.la 
srptool_LDADD += $(LIBOPTS_LDADD) 
noinst_LTLIBRARIES += libcmd-srp.la
libcmd_srp_la_CFLAGS =
libcmd_srp_la_SOURCES = srptool-args.def srptool-args.c srptool-args.h
endif

if ENABLE_OCSP
ocsptool_SOURCES = ocsptool.c ocsptool-common.h ocsptool-common.c \
	socket.c socket.h
ocsptool_LDADD = ../lib/libgnutls.la libcmd-ocsp.la ../gl/libgnu.la 
ocsptool_LDADD += $(LIBOPTS_LDADD) $(LTLIBINTL) $(GETADDRINFO_LIB)
noinst_LTLIBRARIES += libcmd-ocsp.la
libcmd_ocsp_la_CFLAGS =
libcmd_ocsp_la_SOURCES = ocsptool-args.def ocsptool-args.h ocsptool-args.c
endif

psktool_SOURCES = psk.c
psktool_LDADD = ../lib/libgnutls.la libcmd-psk.la ../gl/libgnu.la 
psktool_LDADD += $(LIBOPTS_LDADD) $(LTLIBINTL)
noinst_LTLIBRARIES += libcmd-psk.la
libcmd_psk_la_CFLAGS = 
libcmd_psk_la_SOURCES = psk-args.def psk-args.c psk-args.h

BENCHMARK_SRCS = benchmark-cipher.c benchmark.c benchmark.h benchmark-tls.c

gnutls_cli_SOURCES = cli.c common.h common.c \
	socket.c socket.h ocsptool-common.c \
	$(PKCS11_SRCS) $(BENCHMARK_SRCS)
gnutls_cli_LDADD = ../lib/libgnutls.la
gnutls_cli_LDADD += libcmd-cli.la ../gl/libgnu.la $(LIBOPTS_LDADD) $(LTLIBINTL)
gnutls_cli_LDADD += $(LIBSOCKET) $(GETADDRINFO_LIB) $(LIB_CLOCK_GETTIME) \
	 $(SERVENT_LIB)
noinst_LTLIBRARIES += libcmd-cli.la
libcmd_cli_la_CFLAGS = 
libcmd_cli_la_SOURCES = cli-args.def cli-args.c cli-args.h

gnutls_cli_debug_SOURCES = tls_test.c tests.h tests.c \
		socket.c socket.h common.h common.c \
		$(PKCS11_SRCS)
gnutls_cli_debug_LDADD = ../lib/libgnutls.la libcmd-cli-debug.la 
gnutls_cli_debug_LDADD += $(LIBOPTS_LDADD) $(LTLIBINTL)
gnutls_cli_debug_LDADD += ../gl/libgnu.la $(LIBSOCKET) $(GETADDRINFO_LIB)
noinst_LTLIBRARIES += libcmd-cli-debug.la
libcmd_cli_debug_la_CFLAGS =
libcmd_cli_debug_la_SOURCES = cli-debug-args.def cli-debug-args.c cli-debug-args.h

#certtool

certtool_SOURCES = certtool.c dh.c certtool-common.c $(PKCS11_SRCS)
certtool_LDADD = ../lib/libgnutls.la 
certtool_LDADD += libcmd-certtool.la ../gl/libgnu.la

noinst_LTLIBRARIES += libcmd-certtool.la
libcmd_certtool_la_CFLAGS =
libcmd_certtool_la_SOURCES = certtool-args.c certtool-args.def certtool-args.h	\
	certtool-cfg.h certtool-cfg.c
libcmd_certtool_la_LIBADD = ../gl/libgnu.la $(LTLIBREADLINE) 
libcmd_certtool_la_LIBADD += $(LIBOPTS_LDADD) $(LTLIBINTL)
libcmd_certtool_la_LIBADD += ../lib/libgnutls.la 
libcmd_certtool_la_LIBADD += ../gl/libgnu.la $(INET_PTON_LIB)

# p11 tool
if ENABLE_PKCS11

p11tool_SOURCES = p11tool-args.def p11tool.c pkcs11.c certtool-common.c p11tool.h $(PKCS11_SRCS)
p11tool_LDADD = ../lib/libgnutls.la $(LIBOPTS_LDADD) $(LTLIBINTL)
p11tool_LDADD += libcmd-p11tool.la ../gl/libgnu.la

noinst_LTLIBRARIES += libcmd-p11tool.la
libcmd_p11tool_la_CFLAGS =
libcmd_p11tool_la_SOURCES = p11tool-args.def p11tool-args.c p11tool-args.h \
	certtool-cfg.h certtool-cfg.c
libcmd_p11tool_la_LIBADD = ../gl/libgnu.la $(LTLIBREADLINE)
libcmd_p11tool_la_LIBADD += ../lib/libgnutls.la
libcmd_p11tool_la_LIBADD += ../gl/libgnu.la $(INET_PTON_LIB)

endif # ENABLE_PKCS11

BUILT_SOURCES = ocsptool-args.c p11tool-args.c psk-args.c cli-debug-args.c \
		cli-args.c serv-args.c srptool-args.c certtool-args.c

ocsptool-args.c: $(srcdir)/args-std.def $(srcdir)/ocsptool-args.def
	-autogen ocsptool-args.def
p11tool-args.c: $(srcdir)/args-std.def $(srcdir)/p11tool-args.def
	-autogen p11tool-args.def
psk-args.c: $(srcdir)/args-std.def $(srcdir)/psk-args.def
	-autogen psk-args.def
cli-debug-args.c: $(srcdir)/args-std.def $(srcdir)/cli-debug-args.def
	-autogen cli-debug-args.def
cli-args.c: $(srcdir)/args-std.def $(srcdir)/cli-args.def
	-autogen cli-args.def
serv-args.c: $(srcdir)/args-std.def $(srcdir)/serv-args.def
	-autogen serv-args.def
srptool-args.c: $(srcdir)/args-std.def $(srcdir)/srptool-args.def
	-autogen srptool-args.def
certtool-args.c: $(srcdir)/args-std.def $(srcdir)/certtool-args.def
	-autogen certtool-args.def
