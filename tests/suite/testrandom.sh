#!/bin/sh

# Copyright (C) 2012 Free Software Foundation, Inc.
#
# Author: Nikos Mavrogiannopoulos
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

srcdir="${srcdir:-.}"
CERTTOOL="${CERTTOOL:-../../src/certtool${EXEEXT}}"

if ! test -x "${CERTTOOL}"; then
	exit 77
fi

if ! test -z "${VALGRIND}"; then
	VALGRIND="${LIBTOOL:-libtool} --mode=execute ${VALGRIND}"
fi

counter=0
file=test.out

counter=0

echo "Testing verification with randomly generated certificates..."
while [ ${counter} -lt 400 ]; do
	counter=`expr ${counter} + 1`

	"${srcdir}/x509random.pl" > "${file}"
	${VALGRIND} "${CERTTOOL}" -i --inder --infile "${file}" --outfile "${file}.pem" >/dev/null
	if test $? != 0; then
		continue
	fi

	cat "${file}.pem" "${srcdir}/../certs/ca-cert-ecc.pem" > "${file}-chain.pem"

	${VALGRIND} "${CERTTOOL}" -e --infile "${file}-chain.pem" >/dev/null 2>&1
	ret=$?
	if [ ${ret} != 1 ]; then
		echo "Succeeded verification with ${file}-chain.pem!"
		exit 1
	fi
	rm -f "${file}.pem" "${file}-chain.pem"
done


echo "Testing with randomly generated certificates..."
while [ ${counter} -lt 200 ]; do
	"${srcdir}/x509random.pl" > "${file}"
	${VALGRIND} "${CERTTOOL}" -i --inder --infile "${file}" >/dev/null
	ret=$?
	if test ${ret} != 0 && test ${ret} != 1; then
		echo "Unknown exit code with ${file}"
		exit 1
	fi

	counter=`expr ${counter} + 1`
done

counter=0

echo "Testing with random ASN.1 data..."
while [ ${counter} -lt 200 ]; do
	"${srcdir}/asn1random.pl" > "${file}"
	${VALGRIND} "${CERTTOOL}" -i --inder --infile "${file}" >/dev/null 2>/dev/null
	ret=$?
	if test ${ret} != 0 && test ${ret} != 1; then
		echo "Unknown exit code with ${file}"
		exit 1
	fi

	counter=`expr ${counter} + 1`
done

rm -f "${file}"

exit 0
