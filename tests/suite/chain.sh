#!/bin/sh

# Copyright (C) 2004-2012 Free Software Foundation, Inc.
#
# Author: Simon Josefsson
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

cd x509paths

CERTTOOL="${CERTTOOL:-../../../src/certtool${EXEEXT}}"

if ! test -x "${CERTTOOL}"; then
	exit 77
fi

if ! test -z "${VALGRIND}"; then
	VALGRIND="${LIBTOOL:-libtool} --mode=execute ${VALGRIND} --error-exitcode=15"
fi

SUCCESS=" 1 4 7 12 15 16 17 18 24 26 27 30 33 56 57 62 63 "
FAILURE=" 2 3 5 6 8 9 10 11 13 14 19 20 21 22 23 25 28 29 31 32 54 55 58 59 60 61 "
KNOWN_BUGS=" 15 16 17 18 19 31 32 "

test -d X509tests || tar xfz x509tests.tgz
mkdir -p chains
RET=0

i=1
while test -d X509tests/test${i}; do
	find X509tests/test${i} -name *.crl -print0 |sort -r -z|xargs -n1 --null ${VALGRIND}  "${CERTTOOL}" --crl-info --inder --infile > chains/chain${i}.pem 
	find X509tests/test${i} -name E*.crt -print0 |sort -r -z|xargs -n1 --null ${VALGRIND}  "${CERTTOOL}" --certificate-info --inder --infile >> chains/chain${i}.pem 
	if test "${i}" -gt 1; then
		find X509tests/test${i} -name I*.crt -print0 |sort -r -z|xargs -n1 --null ${VALGRIND}  "${CERTTOOL}" --certificate-info --inder --infile >> chains/chain${i}.pem 
	fi
	find X509tests/test${i} -name T*.crt -print0 |sort -r -z|xargs -n1 --null ${VALGRIND}  "${CERTTOOL}" --certificate-info --inder --infile >> chains/chain${i}.pem 
	${VALGRIND} "${CERTTOOL}" -e --infile chains/chain${i}.pem > out
	rc=$?
	if test $rc != 0 && test $rc != 1; then
		echo "Chain ${i} FATAL failure."
		exit 1
	else
		if echo "$KNOWN_BUGS" | grep " ${i} " > /dev/null; then
				echo "Chain ${i} verification was skipped due to known bug."
		elif echo "$SUCCESS" | grep " ${i} " > /dev/null; then
			if grep 'Chain verification output:' out | grep -v 'Chain verification output: Verified\.' > /dev/null; then
				echo "Chain ${i} verification failure UNEXPECTED."
				exit 1
			else
				echo "Chain ${i} verification success as expected."
			fi
		elif echo "$FAILURE" | grep " ${i} " >/dev/null; then
			if grep 'Chain verification output:' out | grep -v 'Chain verification output: Verified\.' > /dev/null; then
				echo "Chain ${i} verification failure as expected."
			else
				echo "Chain ${i} verification success UNEXPECTED. "
				exit 1
			fi
		else
			echo "Chain ${i} unclassified."
		fi
	fi
	i=`expr ${i} + 1`
done
rm -f out

exit ${RET}
