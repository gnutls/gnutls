#!/bin/sh

# Copyright (C) 2017 Red Hat, Inc.
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
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>

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
OUTFILE2=out2-cms.$$.tmp

. ${srcdir}/../scripts/common.sh

skip_if_no_datefudge

KEY="${srcdir}/../certs/ed25519.pem"
CMS="${srcdir}/../certs/cert-ed25519.pem"

# Test verification of saved file
FILE="${srcdir}/data/pkcs7-eddsa-sig.p7s"
${VALGRIND} "${CMSTOOL}" --inder --verify --load-certificate "${CMS}" --infile "${FILE}"
rc=$?

if test "${rc}" != "0"; then
	echo "${FILE}: PKCS7 struct verification failed"
	exit ${rc}
fi

# Test signing
FILE="signing"
${VALGRIND} "${CMSTOOL}" --sign --load-privkey  "${KEY}" --load-certificate "${CMS}" --infile "${srcdir}/data/pkcs7-detached.txt" >"${OUTFILE}"
rc=$?

if test "${rc}" != "0"; then
	echo "${FILE}: PKCS7 struct signing failed"
	exit ${rc}
fi

FILE="signing-verify"
${VALGRIND} "${CMSTOOL}" --verify --load-certificate "${CMS}" <"${OUTFILE}"
rc=$?

if test "${rc}" != "0"; then
	echo "${FILE}: PKCS7 struct signing failed verification"
	exit ${rc}
fi

#check extraction of embedded data in signature
FILE="signing-verify-data"
${VALGRIND} "${CMSTOOL}" --verify --show-data --load-certificate "${CMS}" --outfile "${OUTFILE2}" <"${OUTFILE}"
rc=$?

if test "${rc}" != "0"; then
	echo "${FILE}: PKCS7 struct signing failed verification with data"
	exit ${rc}
fi

cmp "${OUTFILE2}" "${srcdir}/data/pkcs7-detached.txt"
rc=$?
if test "${rc}" != "0"; then
	echo "${FILE}: PKCS7 data detaching failed"
	exit ${rc}
fi

FILE="signing-time"
${VALGRIND} "${CMSTOOL}" --detached-sign --time --load-privkey  "${KEY}" --load-certificate "${CMS}" --infile "${srcdir}/data/pkcs7-detached.txt" >"${OUTFILE}"
rc=$?

if test "${rc}" != "0"; then
	echo "${FILE}: PKCS7 struct signing with time failed"
	exit ${rc}
fi

${VALGRIND} "${CMSTOOL}" --info --infile "${OUTFILE}" >"${OUTFILE2}"
grep 'contentType: 06092a864886f70d010701' ${OUTFILE2} >/dev/null 2>&1
if test $? != 0;then
	echo "Content-Type was not set in attributes"
	exit 1
fi

${VALGRIND} "${CMSTOOL}" --info <"${OUTFILE}"|grep "Signing time:" "${OUTFILE}" >/dev/null 2>&1
if test "${rc}" != "0"; then
	echo "${FILE}: PKCS7 struct signing with time failed. No time was found."
	exit ${rc}
fi

FILE="signing-time-verify"
${VALGRIND} "${CMSTOOL}" --verify --load-certificate "${CMS}" --load-data "${srcdir}/data/pkcs7-detached.txt" <"${OUTFILE}"
rc=$?

if test "${rc}" != "0"; then
	echo "${FILE}: PKCS7 struct signing with time failed verification"
	exit ${rc}
fi

rm -f "${OUTFILE}"
rm -f "${OUTFILE2}"

exit 0
