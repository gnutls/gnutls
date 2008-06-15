## Process this file with automake to produce Makefile.in
# Copyright (C) 2007, 2008 Free Software Foundation
#
# This file is part of GNUTLS.
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

if ENABLE_OPENPGP

EXTRA_DIST = ca-public.gpg srv-public-all-signed.gpg srv-secret.gpg	\
	ca-secret.gpg srv-public.gpg srv-public-127.0.0.1-signed.gpg	\
	srv-public-localhost-signed.gpg

# The selftest is disabled until we can make it work under Wine and
# under Debian buildds (problem with 127.0.0.2?).  Just extra-dist it
# for now.
EXTRA_DIST += testcerts
#dist_check_SCRIPTS = testcerts
#TESTS = testcerts

endif
