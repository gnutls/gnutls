#!/bin/bash

# Copyright (C) 2016-2018 Red Hat, Inc.
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
# along with GnuTLS.  If not, see <https://www.gnu.org/licenses/>.

builddir=`pwd`
CLI="${builddir}/../../src/gnutls-cli${EXEEXT}"
SERV="${builddir}/../../src/gnutls-serv${EXEEXT}"

TMPFILE="${builddir}/tls-fuzzer.$$.tmp"
PSKFILE="${builddir}/tls-fuzzer.psk.$$.tmp"

. "${srcdir}/../scripts/common.sh"

if test "${GNUTLS_FORCE_FIPS_MODE}" = 1 ; then
	echo "Cannot run in FIPS140-2 mode"
	exit 77
fi

if ! test -d "${srcdir}/tls-fuzzer/tlsfuzzer" ; then
	exit 77
fi

if test "${PYTHON}" = ":" ; then
	exit 77
fi

eval "${GETPORT}"

pushd "${srcdir}/tls-fuzzer/tlsfuzzer"

wait_for_free_port $PORT

retval=0

tls_fuzzer_prepare

export PYTHONDONTWRITEBYTECODE=never

PYTHONPATH=../python-ecdsa/src:../tlslite-ng:. \
"${PYTHON}" tests/scripts_retention.py ${TMPFILE} ${SERV} 821
retval=$?

rm -f ${TMPFILE}
[ -f "${PSKFILE}" ] && rm -f ${PSKFILE}

popd

exit $retval
