#!/bin/bash

# Copyright (c) 2010-2016, Free Software Foundation, Inc.
# Copyright (c) 2012-2018, Nikos Mavrogiannopoulos
# All rights reserved.
#
# Author: Nikos Mavrogiannopoulos
#
# This file is part of GnuTLS.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors may
# be used to endorse or promote products derived from this software without specific
# prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
# WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

abs_top_srcdir="${abs_top_srcdir:-$(pwd)/../../}"
srcdir="${srcdir:-.}"
CLI="${CLI:-../../src/gnutls-cli${EXEEXT}}"
TMPFILE=testcompat-oldgnutls.$$.tmp

# This assumes a root directory in /usr/local/OLDGNUTLS containing the
# gnutls client and server

if ! test -x "${CLI}"; then
	exit 77
fi

if ! test -z "${VALGRIND}"; then
	VALGRIND="${LIBTOOL:-libtool} --mode=execute ${VALGRIND}"
fi

if test "${WINDIR}" != ""; then
	exit 77
fi

LDPATH=/usr/local/OLDGNUTLS/lib/x86_64-linux-gnu:/usr/local/OLDGNUTLS/usr/lib/x86_64-linux-gnu

. "${srcdir}/../scripts/common.sh"

check_for_datefudge

. "${srcdir}/testcompat-common"

PORT="${PORT:-${RPORT}}"

SERV=/usr/local/OLDGNUTLS/usr/bin/gnutls-serv

if test -z "$OUTPUT";then
OUTPUT=/dev/null
fi

>${OUTPUT}

echo_cmd() {
	tee -a ${OUTPUT} <<<$(echo $1)
}

echo_cmd "Compatibility checks using "`${SERV} version`

echo_cmd "####################################################"
echo_cmd "# Client mode tests (new cli-gnutls 2.12.x server) #"
echo_cmd "####################################################"

run_client_suite() {
	ADD=$1
	PREFIX=""
	if ! test -z "${ADD}"; then
		PREFIX="$(echo $ADD|sed 's/://g'): "
	fi

	eval "${GETPORT}"
	LD_LIBRARY_PATH=$LDPATH launch_server $$ --priority "NORMAL:+SHA256${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" --dhparams "${DH_PARAMS}"
	PID=$!
	wait_server ${PID}

	# Test TLS 1.0 with RSA ciphersuite
	echo "${PREFIX}Checking TLS 1.0 with RSA and AES-128-CBC..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-128-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.0 with RSA and AES-256-CBC..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-256-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	# Test TLS 1.0 with DHE-RSA ciphersuite
	echo "${PREFIX}Checking TLS 1.0 with DHE-RSA..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+DHE-RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.2 with RSA and AES-128-CBC..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-128-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.2 with RSA and AES-256-CBC..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-256-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.2 with DHE-RSA..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+DHE-RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.2 with RSA, AES-CBC and long packet..."
	head -c 16384 /dev/zero|tr \\0 a >${TMPFILE}
	echo >>${TMPFILE}
	${VALGRIND} "${CLI}" -d 6 ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-128-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" <${TMPFILE} >/dev/null ||
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.2 with RSA, AES-CBC-SHA256 and long packet..."
	head -c 16384 /dev/zero|tr \\0 a >${TMPFILE}
	echo >>${TMPFILE}
	${VALGRIND} "${CLI}" -d 6 ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-128-CBC:+SIGN-ALL:+COMP-NULL:+SHA256:+VERS-TLS1.2:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" <${TMPFILE} >/dev/null ||
		fail ${PID} "Failed"

	kill ${PID}
	wait
}

run_client_suite

echo_cmd "${PREFIX}Client mode tests were successfully completed"
echo_cmd "${PREFIX}"
echo_cmd "${PREFIX}###############################################"
echo_cmd "${PREFIX}# Server mode tests (new server-old cli)      #"
echo_cmd "${PREFIX}###############################################"
SERV="../../src/gnutls-serv${EXEEXT} -q"
CLI=/usr/local/OLDGNUTLS/usr/bin/gnutls-cli

run_server_suite() {
	ADD=$1
	PREFIX=""
	if ! test -z "${ADD}"; then
		PREFIX="$(echo $ADD|sed 's/://g'): "
	fi

	eval "${GETPORT}"
	launch_server $$ --priority "NORMAL:+SHA256${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" --dhparams "${DH_PARAMS}"
	PID=$!
	wait_server ${PID}

	echo "${PREFIX}Checking TLS 1.0 with RSA and AES-128-CBC..."
	LD_LIBRARY_PATH=$LDPATH "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-128-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.0 with RSA and AES-256-CBC..."
	LD_LIBRARY_PATH=$LDPATH "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-256-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.0 with DHE-RSA..."
	LD_LIBRARY_PATH=$LDPATH "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+DHE-RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.2 with RSA and AES-128-CBC..."
	LD_LIBRARY_PATH=$LDPATH "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-128-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.2 with RSA and AES-256-CBC..."
	LD_LIBRARY_PATH=$LDPATH "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-256-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.2 with DHE-RSA..."
	LD_LIBRARY_PATH=$LDPATH "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+DHE-RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.2 with RSA, AES-CBC and long packet..."
	head -c 16384 /dev/zero|tr \\0 a >${TMPFILE}
	echo >>${TMPFILE}
	LD_LIBRARY_PATH=$LDPATH "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-128-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" <${TMPFILE} >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.2 with RSA, AES-CBC-SHA256 and long packet..."
	head -c 16384 /dev/zero|tr \\0 a >${TMPFILE}
	echo >>${TMPFILE}
	LD_LIBRARY_PATH=$LDPATH "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-128-CBC:+SIGN-ALL:+COMP-NULL:+SHA256:+VERS-TLS1.2:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" <${TMPFILE} >/dev/null || \
		fail ${PID} "Failed"

	kill ${PID}
	wait

}

run_server_suite

rm -f ${TMPFILE}

exit 0
