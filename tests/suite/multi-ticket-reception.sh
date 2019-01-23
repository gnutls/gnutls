#!/bin/sh

# Copyright (C) 2019 Red Hat, Inc.
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
TLSPY_SERV="${srcdir}/tls-fuzzer/tlslite-ng/scripts/tls.py"
PYPATH="${srcdir}/tls-fuzzer/tlsfuzzer/"
CLI="${CLI:-../../src/gnutls-cli${EXEEXT}}"
unset RETCODE

if ! test -x "${TLSPY_SERV}"; then
	exit 77
fi

if ! test -x "${CLI}"; then
	exit 77
fi

if test "${WINDIR}" != ""; then
	exit 77
fi 

if ! test -z "${VALGRIND}"; then
	VALGRIND="${LIBTOOL:-libtool} --mode=execute ${VALGRIND} --error-exitcode=15"
fi

. "${srcdir}/../scripts/common.sh"

KEY1=${srcdir}/tls-fuzzer/tlslite-ng/tests/serverX509Key.pem
CERT1=${srcdir}/tls-fuzzer/tlsfuzzer/tests/serverX509Cert.pem 

#create links necessary for tlslite to function
pushd "${srcdir}/tls-fuzzer/tlsfuzzer"
test -L ecdsa || ln -s ../python-ecdsa/src/ecdsa ecdsa
test -L tlslite || ln -s ../tlslite-ng/tlslite tlslite 2>/dev/null
popd

echo "Checking whether receiving 1 ticket succeeds (sanity)"

eval "${GETPORT}"
PYTHONPATH="${PYPATH}" ${TLSPY_SERV} server --tickets 1 -k ${KEY1} -c ${CERT1} 127.0.0.1:${PORT} &
PID=$!
wait_server ${PID}

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --priority NORMAL:-VERS-ALL:+VERS-TLS1.3 --insecure </dev/null || \
	fail ${PID} "1. handshake should have succeeded!"


kill ${PID}
wait

echo "Checking whether receiving 3 tickets in the same record succeeds"

eval "${GETPORT}"
PYTHONPATH="${PYPATH}" ${TLSPY_SERV} server --tickets 3 -k ${KEY1} -c ${CERT1} 127.0.0.1:${PORT} &
PID=$!
wait_server ${PID}

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --priority NORMAL:-VERS-ALL:+VERS-TLS1.3 --insecure </dev/null || \
	fail ${PID} "2. handshake should have succeeded!"


kill ${PID}
wait

echo "Checking whether receiving multiple tickets that span many records succeeds"

eval "${GETPORT}"
PYTHONPATH="${PYPATH}" ${TLSPY_SERV} server --tickets 1512 -k ${KEY1} -c ${CERT1} 127.0.0.1:${PORT} &
PID=$!
wait_server ${PID}

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --priority NORMAL:-VERS-ALL:+VERS-TLS1.3 --insecure </dev/null || \
	fail ${PID} "3. handshake should have succeeded!"


kill ${PID}
wait


exit 0
