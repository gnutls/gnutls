#!/bin/sh

# Copyright (C) 2016 Red Hat, Inc.
#
# This file is part of GnuTLS.
#
# GnuTLS is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at
# your option) any later version.
#
# GnuTLS is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GnuTLS; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#set -e

srcdir="${srcdir:-.}"
CMSTOOL="${CMSTOOL:-../../src/cmstool${EXEEXT}}"
DIFF="${DIFF:-diff -b -B}"

if ! test -x "${CMSTOOL}"; then
	exit 77
fi

# MD5 is not available under FIPS
if test "${GNUTLS_FORCE_FIPS_MODE}" = 1;then
	exit 77
fi

if ! test -z "${VALGRIND}"; then
	VALGRIND="${LIBTOOL:-libtool} --mode=execute ${VALGRIND} --error-exitcode=15"
fi

OUTFILE=out-cms.$$.tmp
OUTFILE2=out2-cms.$$.tmp

# Test digest with MD5
FILE="digest"
${VALGRIND} "${CMSTOOL}" --digest --hash md5 --infile "${srcdir}/data/pkcs7-detached.txt" >"${OUTFILE}"
rc=$?

if test "${rc}" != "0"; then
	echo "${FILE}: PKCS7 struct digest with MD5 failed"
	exit ${rc}
fi

FILE="digest-verify"
${VALGRIND} "${CMSTOOL}" --verify-digest <"${OUTFILE}"
rc=$?

if test "${rc}" != "1"; then
	echo "${FILE}: PKCS7 struct digest succeeded verification with MD5"
	exit ${rc}
fi

FILE="digest-verify"
${VALGRIND} "${CMSTOOL}" --verify-digest --verify-allow-broken <"${OUTFILE}"
rc=$?

if test "${rc}" != "0"; then
	echo "${FILE}: PKCS7 struct digest failed with MD5 and allow-broken"
	exit ${rc}
fi

rm -f "${OUTFILE}"
rm -f "${OUTFILE2}"

exit 0
