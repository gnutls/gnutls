#!/bin/bash

# Copyright (C) 2010-2012 Free Software Foundation, Inc.
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
SERV="${SERV:-../../src/gnutls-serv${EXEEXT}}"
CLI="${CLI:-../../src/gnutls-cli${EXEEXT}}"
unset RETCODE

if ! test -x "${SERV}"; then
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


SERV="${SERV} -q"

. "${srcdir}/../scripts/common.sh"

echo "Checking Safe renegotiation"

eval "${GETPORT}"
launch_server $$ --echo --priority NORMAL:+ANON-DH:%PARTIAL_RENEGOTIATION --dhparams "${srcdir}/params.dh"
PID=$!
wait_server ${PID}

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --rehandshake --priority NONE:+AES-128-CBC:+MD5:+SHA1:+VERS-TLS1.0:+ANON-DH:+COMP-NULL:%SAFE_RENEGOTIATION </dev/null >/dev/null || \
	fail ${PID} "0. Renegotiation should have succeeded!"

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --rehandshake --priority NORMAL:+ANON-DH:%SAFE_RENEGOTIATION </dev/null >/dev/null || \
	fail ${PID} "1. Safe rehandshake should have succeeded!"

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --rehandshake --priority NORMAL:+ANON-DH:%UNSAFE_RENEGOTIATION </dev/null >/dev/null || \
	fail ${PID} "2. Unsafe rehandshake should have succeeded!"

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --priority NORMAL:+ANON-DH:%DISABLE_SAFE_RENEGOTIATION </dev/null >/dev/null || \
	fail ${PID} "3. Unsafe negotiation should have succeeded!"

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --rehandshake --priority NORMAL:+ANON-DH:%DISABLE_SAFE_RENEGOTIATION </dev/null >/dev/null && \
	fail ${PID} "4. Unsafe renegotiation should have failed!"


kill ${PID}
wait

eval "${GETPORT}"
launch_server $$  --echo --priority NORMAL:+ANON-DH:%SAFE_RENEGOTIATION --dhparams "${srcdir}/params.dh"
PID=$!
wait_server ${PID}

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --rehandshake --priority NORMAL:+ANON-DH:%SAFE_RENEGOTIATION </dev/null >/dev/null || \
	fail ${PID} "5. Safe rehandshake should have succeeded!"

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --rehandshake --priority NORMAL:+ANON-DH:%UNSAFE_RENEGOTIATION </dev/null >/dev/null || \
	fail ${PID} "6. Unsafe rehandshake should have succeeded!"

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --priority NORMAL:+ANON-DH:%DISABLE_SAFE_RENEGOTIATION </dev/null >/dev/null && \
	fail ${PID} "7. Unsafe negotiation should have failed!"

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --rehandshake --priority NORMAL:+ANON-DH:%DISABLE_SAFE_RENEGOTIATION </dev/null >/dev/null && \
	fail ${PID} "8. Unsafe renegotiation should have failed!"

kill ${PID}
wait

eval "${GETPORT}"
launch_server $$ --echo --priority NORMAL:+ANON-DH:%DISABLE_SAFE_RENEGOTIATION --dhparams "${srcdir}/params.dh"
PID=$!
wait_server ${PID}

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --priority NORMAL:+ANON-DH:%SAFE_RENEGOTIATION </dev/null >/dev/null && \
	fail ${PID} "9. Initial connection should have failed!"

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --priority NORMAL:+ANON-DH:%UNSAFE_RENEGOTIATION </dev/null >/dev/null || \
	fail ${PID} "10. Unsafe connection should have succeeded!"

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --priority NORMAL:+ANON-DH:%DISABLE_SAFE_RENEGOTIATION </dev/null >/dev/null || \
	fail ${PID} "11. Unsafe negotiation should have succeeded!"

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --rehandshake --priority NORMAL:+ANON-DH:%DISABLE_SAFE_RENEGOTIATION </dev/null >/dev/null || \
	fail ${PID} "12. Unsafe renegotiation should have succeeded!"

kill ${PID}
wait

exit 0
