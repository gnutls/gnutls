#  GNUTLS -- Guile bindings for GnuTLS.
#  Copyright (C) 2007  Free Software Foundation
#
#  GNUTLS is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 2.1 of the License, or (at your option) any later version.
#
#  GNUTLS is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public
#  License along with GNUTLS; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

GUILE_FOR_BUILD = $(GUILE) -L $(top_srcdir)/guile/modules

noinst_HEADERS = errors.h utils.h

EXTRA_DIST =					\
  make-enum-map.scm make-smob-types.scm		\
  make-enum-header.scm make-smob-header.scm	\
  make-session-priorities.scm

BUILT_SOURCES = enum-map.i.c smob-types.i.c enums.h smobs.h	\
		priorities.i.c					\
		extra-smobs.h extra-enums.h			\
		extra-enum-map.i.c extra-smob-types.i.c		\
                core.c.x errors.c.x extra.c.x

CLEANFILES = $(BUILT_SOURCES)

lib_LTLIBRARIES = libguile-gnutls-v-0.la libguile-gnutls-extra-v-0.la

GNULIB_LDFLAGS = -L$(top_builddir)/lgl -llgnu
GNULIB_CFLAGS  = -I$(top_builddir)/lgl -I$(top_srcdir)/lgl

libguile_gnutls_v_0_la_SOURCES = core.c errors.c utils.c
libguile_gnutls_v_0_la_CFLAGS =				\
  $(GNULIB_CFLAGS) $(GUILE_CFLAGS) $(LIBGNUTLS_CFLAGS)
libguile_gnutls_v_0_la_LDFLAGS =			\
  $(GNULIB_LDFLAGS) $(GUILE_LDFLAGS) $(LIBGNUTLS_LIBS)

libguile_gnutls_extra_v_0_la_SOURCES = extra.c
libguile_gnutls_extra_v_0_la_CFLAGS =		\
  $(GNULIB_CFLAGS) $(GUILE_CFLAGS)		\
  $(LIBGNUTLS_CFLAGS) $(LIBGNUTLS_EXTRA_CFLAGS)
libguile_gnutls_extra_v_0_la_LDFLAGS =		\
  $(GNULIB_LDFLAGS) $(GUILE_LDFLAGS)		\
  $(LIBGNUTLS_LIBS) $(LIBGNUTLS_EXTRA_LIBS)	\
  -L$(builddir) -lguile-gnutls-v-0

AM_CPPFLAGS = -I$(builddir)

if HAVE_GCC

# Generated `.x' files and Guile's `scm_c_define_gsubr ()' require
# `-Wno-strict-prototypes'.
libguile_gnutls_v_0_la_CFLAGS += -Wno-strict-prototypes
libguile_gnutls_extra_v_0_la_CFLAGS += -Wno-strict-prototypes

endif

enums.h: $(srcdir)/make-enum-header.scm
	$(GUILE_FOR_BUILD) $^ > $@

enum-map.i.c: $(srcdir)/make-enum-map.scm
	$(GUILE_FOR_BUILD) $^ > $@

smobs.h: $(srcdir)/make-smob-header.scm
	$(GUILE_FOR_BUILD) $^ > $@

smob-types.i.c: $(srcdir)/make-smob-types.scm
	$(GUILE_FOR_BUILD) $^ > $@

priorities.i.c: $(srcdir)/make-session-priorities.scm
	$(GUILE_FOR_BUILD) $^ > $@


# GnuTLS-extra

extra-enums.h: $(srcdir)/make-enum-header.scm
	$(GUILE_FOR_BUILD) $^ extra > $@

extra-enum-map.i.c: $(srcdir)/make-enum-map.scm
	$(GUILE_FOR_BUILD) $^ extra > $@

extra-smobs.h: $(srcdir)/make-smob-header.scm
	$(GUILE_FOR_BUILD) $^ extra > $@

extra-smob-types.i.c: $(srcdir)/make-smob-types.scm
	$(GUILE_FOR_BUILD) $^ extra > $@


# C file snarfing.

snarfcppopts = $(DEFS) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) \
	       $(CFLAGS) $(AM_CFLAGS)

SUFFIXES = .x
%.c.x: %.c
	$(guile_snarf) -o $@ $< $(snarfcppopts)
