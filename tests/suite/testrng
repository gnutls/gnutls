#!/bin/sh

# Copyright (C) 2014 Nikos Mavrogiannopoulos
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

if ! test -x "/usr/bin/dieharder"; then
	exit 77
fi

VERSION=`dieharder -l|grep version|cut -d ' ' -f 6`

if test "$1" = "full"; then
	OPTIONS="-a"
else
	if test "${VERSION}" = "2.28.1"; then
		OPTIONS="-d 5"
		OPTIONS2="-d 10"
	else
		OPTIONS="-d 202"
		OPTIONS2="-d 10"
	fi
fi

OUTFILE=rng.log
RNGFILE=rng.out
RNGFILE2=rng2.out

rm -f "${OUTFILE}"
rm -f "${RNGFILE}"
rm -f "${RNGFILE2}"

. "${srcdir}/../scripts/common.sh"


RINPUTNO=`dieharder -g -1|grep file_input_raw|cut -d '|' -f 2|cut -d ' ' -f 1`

if test -z "${RINPUTNO}"; then
	echo "Cannot determine dieharder option for raw file input, assuming 201"
	RINPUTNO=201
fi

echo ""
echo "Testing nonce PRNG"

./rng nonce 64 "${RNGFILE}"
./rng nonce 64 "${RNGFILE2}"
cmp "${RNGFILE}" "${RNGFILE2}"  >/dev/null 2>&1
ret=$?

if test ${ret} = 0; then
	echo "numbers are repeated in nonce!"
	exit 1
fi

./rng nonce 100000000 "${RNGFILE}"

dieharder -f "${RNGFILE}" -g ${RINPUTNO} ${OPTIONS} >"${OUTFILE}" 2>&1
if ! test -z "${OPTIONS2}"; then
	dieharder -f "${RNGFILE}" -g ${RINPUTNO} ${OPTIONS2} >>"${OUTFILE}" 2>&1
fi
grep FAILED "${OUTFILE}" >/dev/null 2>&1
ret=$?

if test "${ret}" = "0"; then
	echo "test failed for nonce"
	exit 1
fi

grep PASSED "${OUTFILE}" >/dev/null 2>&1
ret=$?

if test "${ret}" != "0"; then
	echo "could not run dieharder test?"
	exit 1
fi

cat "${OUTFILE}"
rm -f "${OUTFILE}"
echo ""
echo "Testing key PRNG"

./rng key 64 "${RNGFILE}"
./rng key 64 "${RNGFILE2}"
cmp "${RNGFILE}" "${RNGFILE2}" >/dev/null 2>&1
ret=$?

if test ${ret} = 0; then
	echo "numbers are repeated in nonce!"
	exit 1
fi

./rng key 100000000 "${RNGFILE}"

dieharder -f "${RNGFILE}" -g ${RINPUTNO} ${OPTIONS} >"${OUTFILE}" 2>&1
if ! test -z "${OPTIONS2}"; then
	dieharder -f "${RNGFILE}" -g ${RINPUTNO} ${OPTIONS2} >>"${OUTFILE}" 2>&1
fi
grep FAILED "${OUTFILE}" >/dev/null 2>&1 
ret=$?


if test "${ret}" = "0"; then
	echo "test failed for key"
	exit 1
fi

grep PASSED "${OUTFILE}" >/dev/null 2>&1
ret=$?

if test "${ret}" != "0"; then
	echo "could not run dieharder test?"
	exit 1
fi

cat "${OUTFILE}"
rm -f "${OUTFILE}"
echo ""
echo "Testing /dev/zero PRNG"
dd if=/dev/zero of="${RNGFILE}" bs=4 count=10000000 >/dev/null 2>&1

dieharder -f "${RNGFILE}" -g ${RINPUTNO} ${OPTIONS} >"${OUTFILE}" 2>&1
if ! test -z "${OPTIONS2}"; then
	dieharder -f "${RNGFILE}" -g ${RINPUTNO} ${OPTIONS2} >>"${OUTFILE}" 2>&1
fi
grep PASSED "${OUTFILE}" >/dev/null 2>&1 
ret=$?

if test "${ret}" = "0"; then
	echo "test succeeded for /dev/zero!!!"
	exit 1
fi

grep FAILED "${OUTFILE}" >/dev/null 2>&1
ret=$?

if test "${ret}" != "0"; then
	echo "could not run dieharder test?"
	exit 1
fi

cat "${OUTFILE}"
rm -f "${OUTFILE}"
rm -f "${RNGFILE}"
rm -f "${RNGFILE2}"

exit 0
