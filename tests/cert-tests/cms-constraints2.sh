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

if ! test -z "${VALGRIND}"; then
	VALGRIND="${LIBTOOL:-libtool} --mode=execute ${VALGRIND} --error-exitcode=15"
fi

OUTFILE=out-cms.$$.tmp

. ${srcdir}/../scripts/common.sh

skip_if_no_datefudge


FILE="signing"
echo "test: $FILE"
${VALGRIND} "${CMSTOOL}" --sign --include-cert --load-privkey  "${srcdir}/data/code-signing-cert.pem" --load-certificate "${srcdir}/data/code-signing-cert.pem" --infile "${srcdir}/data/pkcs7-detached.txt" >"${OUTFILE}"
rc=$?

if test "${rc}" != "0"; then
	echo "${FILE}: PKCS7 struct signing failed"
	exit ${rc}
fi

FILE="signing-verify-no-purpose"
echo ""
echo "test: $FILE"
datefudge -s "2015-1-10" \
${VALGRIND} "${CMSTOOL}" --verify --load-certificate "${srcdir}/data/code-signing-cert.pem" <"${OUTFILE}"
rc=$?

if test "${rc}" != "0"; then
	echo "${FILE}: PKCS7 struct signing failed verification (0)"
	exit ${rc}
fi

FILE="signing-verify-valid-purpose"
echo ""
echo "test: $FILE"
datefudge -s "2015-1-10" \
${VALGRIND} "${CMSTOOL}" --verify-purpose 1.3.6.1.5.5.7.3.3 --verify --load-certificate "${srcdir}/data/code-signing-cert.pem" <"${OUTFILE}"
rc=$?

if test "${rc}" != "0"; then
	echo "${FILE}: PKCS7 struct signing failed verification (1)"
	exit ${rc}
fi

FILE="signing-verify-invalid-purpose"
echo ""
echo "test: $FILE"
datefudge -s "2015-1-10" \
${VALGRIND} "${CMSTOOL}" --verify-purpose 1.3.6.1.5.5.7.3.1 --verify --load-certificate "${srcdir}/data/code-signing-cert.pem" <"${OUTFILE}"
rc=$?

if test "${rc}" = "0"; then
	echo "${FILE}: PKCS7 struct signing failed verification (2)"
	exit 1
fi

FILE="signing-verify-invalid-date-1"
echo ""
echo "test: $FILE"
datefudge -s "2011-1-10" \
${VALGRIND} "${CMSTOOL}" --verify-purpose 1.3.6.1.5.5.7.3.3 --verify --load-certificate "${srcdir}/data/code-signing-cert.pem" <"${OUTFILE}"
rc=$?

if test "${rc}" = "0"; then
	echo "${FILE}: PKCS7 struct signing failed verification (3)"
	exit 1
fi

FILE="signing-verify-invalid-date-2"
echo ""
echo "test: $FILE"
datefudge -s "2018-1-10" \
${VALGRIND} "${CMSTOOL}" --verify-purpose 1.3.6.1.5.5.7.3.3 --verify --load-certificate "${srcdir}/data/code-signing-cert.pem" <"${OUTFILE}"
rc=$?

if test "${rc}" = "0"; then
	echo "${FILE}: PKCS7 struct signing failed verification (4)"
	exit 1
fi

rm -f "${OUTFILE}"

exit 0
