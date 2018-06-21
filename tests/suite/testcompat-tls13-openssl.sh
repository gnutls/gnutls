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
unset RETCODE

if ! test -x "${CLI}"; then
	exit 77
fi

if ! test -z "${VALGRIND}"; then
	VALGRIND="${LIBTOOL:-libtool} --mode=execute ${VALGRIND}"
fi

if test "${WINDIR}" != ""; then
	exit 77
fi

. "${srcdir}/../scripts/common.sh"

check_for_datefudge

. "${srcdir}/testcompat-common"

PORT="${PORT:-${RPORT}}"

export LD_LIBRARY_PATH=${abs_top_srcdir}/devel/openssl
echo LD_LIBRARY_PATH=$LD_LIBRARY_PATH
SERV=../../devel/openssl/apps/openssl
OPENSSL_CLI="$SERV"

if test -z "$OUTPUT";then
OUTPUT=/dev/null
fi

>${OUTPUT}

echo_cmd() {
	tee -a ${OUTPUT} <<<$(echo $1)
}

echo_cmd "Compatibility checks using "`${SERV} version`

echo_cmd "#################################################"
echo_cmd "# Client mode tests (gnutls cli-openssl server) #"
echo_cmd "#################################################"

OCIPHERSUITES="TLS_AES_128_CCM_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_8_SHA256"

run_client_suite() {
	ADD=$1
	PREFIX=""
	if ! test -z "${ADD}"; then
		PREFIX="$(echo $ADD|sed 's/://g'): "
	fi


	eval "${GETPORT}"
	launch_bare_server $$ s_server -ciphersuites ${OCIPHERSUITES} -groups 'X25519:P-256:X448:P-521:P-384' -quiet -www -accept "${PORT}" -keyform pem -certform pem ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" -CAfile "${CA_CERT}"
	PID=$!
	wait_server ${PID}

	#AES-128-CCM
	for i in AES-128-GCM AES-256-GCM CHACHA20-POLY1305 AES-128-CCM AES-128-CCM-8;do
		echo_cmd "${PREFIX}Checking TLS 1.3 with ${i}..."
		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+${i}${ADD}" --insecure </dev/null >>${OUTPUT} || \
			fail ${PID} "Failed"
	done

	for i in GROUP-X25519 GROUP-SECP256R1 GROUP-SECP384R1 GROUP-SECP521R1;do
		echo_cmd "${PREFIX}Checking TLS 1.3 with $i..."
		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+${i}${ADD}" --insecure </dev/null >>${OUTPUT} || \
			fail ${PID} "Failed"
	done

	echo_cmd "${PREFIX}Checking TLS 1.3 with double rekey..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --insecure --inline-commands <<<$(echo -e "^rekey^\n^rekey1^\nGET / HTTP/1.0\r\n\r\n") >>${OUTPUT} || \
		fail ${PID} "Failed"

	# Try hello retry request
	echo_cmd "${PREFIX}Checking TLS 1.3 with HRR..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --single-key-share --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-FFDHE2048:+GROUP-FFDHE4096:+GROUP-SECP256R1${ADD}" --insecure </dev/null >>${OUTPUT} || \
		fail ${PID} "Failed"

	kill ${PID}
	wait


	#test PSK ciphersuites
	# disabled as I do not seem to be able to connect to openssl s_server with PSK
	eval "${GETPORT}"
	launch_bare_server $$ s_server -quiet -www -accept "${PORT}" -psk_identity ${PSKID} -psk ${PSKKEY} -nocert
	PID=$!
	wait_server ${PID}

# by default only SHA256 is supported under PSK as PRF, so we cannot try all
# ciphers; only the ones which use SHA256 PRF.
	for i in AES-128-GCM;do
# plain PSK with (EC)DHE not supported by openssl
#		echo_cmd "${PREFIX}Checking TLS 1.3 with PSK with ${i}..."
#		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:+PSK:-CIPHER-ALL:+${i}${ADD}" --pskusername ${PSKID} --pskkey ${PSKKEY} </dev/null || \
#			fail ${PID} "Failed"

		echo_cmd "${PREFIX}Checking TLS 1.3 with DHE-PSK with ${i}..."
		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+DHE-PSK:+VERS-TLS1.3:-CIPHER-ALL:+${i}${ADD}" --pskusername ${PSKID} --pskkey ${PSKKEY} </dev/null >>${OUTPUT} || \
			fail ${PID} "Failed"
	done

	kill ${PID}
	wait

	#test client certificates
	eval "${GETPORT}"
	launch_bare_server $$ s_server -cipher "ALL" -quiet -www -accept "${PORT}" -keyform pem -certform pem ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" -Verify 1 -CAfile "${CA_CERT}" >>${OUTPUT} 2>&1
	PID=$!
	wait_server ${PID}

	for i in GROUP-SECP256R1;do
		echo_cmd "${PREFIX}Checking TLS 1.3 with RSA client cert and $i..."
		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+${i}${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >>${OUTPUT} || \
			fail ${PID} "Failed"

		echo_cmd "${PREFIX}Checking TLS 1.3 with secp256r1 client cert and $i..."
		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+${i}${ADD}" --insecure --x509certfile "${ECC_CLI_CERT}" --x509keyfile "${ECC_CLI_KEY}" </dev/null >>${OUTPUT} || \
			fail ${PID} "Failed"

		echo_cmd "${PREFIX}Checking TLS 1.3 with Ed25519 client cert and $i..."
		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+${i}${ADD}" --insecure --x509certfile "${ED25519_CLI_CERT}" --x509keyfile "${ED25519_CLI_KEY}" </dev/null >>${OUTPUT} || \
			fail ${PID} "Failed"

		echo_cmd "${PREFIX}Checking TLS 1.3 with RSA-PSS client cert and $i..."
		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+${i}${ADD}" --insecure --x509certfile "${RSA_PSS_CLI_CERT}" --x509keyfile "${RSA_PSS_CLI_KEY}" </dev/null >>${OUTPUT} || \
			fail ${PID} "Failed"
	done

	kill ${PID}
	wait

	echo_cmd "${PREFIX}Checking TLS 1.3 with Ed25519 certificate..."
	eval "${GETPORT}"
	launch_bare_server $$ s_server -quiet -www -accept "${PORT}" -keyform pem -certform pem ${OPENSSL_DH_PARAMS_OPT} -key "${ED25519_KEY}" -cert "${ED25519_CERT}" -CAfile "${CA_CERT}"
	PID=$!
	wait_server ${PID}

	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --insecure </dev/null >>${OUTPUT} || \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	echo_cmd "${PREFIX}Checking TLS 1.3 with secp256r1 certificate..."
	eval "${GETPORT}"
	launch_bare_server $$ s_server -quiet -www -accept "${PORT}" -keyform pem -certform pem ${OPENSSL_DH_PARAMS_OPT} -key "${ECC_KEY}" -cert "${ECC_CERT}" -CAfile "${CA_CERT}"
	PID=$!
	wait_server ${PID}

#	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509cafile "${CA_CERT}" </dev/null >>${OUTPUT} || \
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --insecure </dev/null >>${OUTPUT} || \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	echo_cmd "${PREFIX}Checking TLS 1.3 with RSA-PSS certificate..."
	eval "${GETPORT}"
	launch_bare_server $$ s_server -quiet -www -accept "${PORT}" -keyform pem -certform pem ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_PSS_KEY}" -cert "${RSA_PSS_CERT}" -CAfile "${CA_CERT}"
	PID=$!
	wait_server ${PID}

#	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509cafile "${CA_CERT}" </dev/null >>${OUTPUT} || \
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --insecure </dev/null >>${OUTPUT} || \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	# Try resumption
	echo_cmd "${PREFIX}Checking TLS 1.3 with resumption..."
	testdir=`create_testdir tls13-openssl-resumption`
	eval "${GETPORT}"
	launch_bare_server $$ s_server -quiet -www -accept "${PORT}" -keyform pem -certform pem ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" -CAfile "${CA_CERT}"
	PID=$!
	wait_server ${PID}

	# ${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:+GROUP-ALL${ADD}" --x509cafile "${CA_CERT}" --inline-commands | tee "${testdir}/client.out" >> ${OUTPUT}
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:+GROUP-ALL${ADD}" --insecure --inline-commands <<< $(echo -e "^resume^\nGET / HTTP/1.0\r\n\r\n")| tee "${testdir}/client.out" >> ${OUTPUT}
	grep '^\*\*\* This is a resumed session' "${testdir}/client.out" || \
		fail ${PID} "Failed"

	kill ${PID}
	wait
	rm -rf "$testdir"

}

run_client_suite

echo_cmd "${PREFIX}Client mode tests were successfully completed"
echo_cmd "${PREFIX}"
echo_cmd "${PREFIX}###############################################"
echo_cmd "${PREFIX}# Server mode tests (gnutls server-openssl cli#"
echo_cmd "${PREFIX}###############################################"
SERV="../../src/gnutls-serv${EXEEXT} -q"

# Note that openssl s_client does not return error code on failure

run_server_suite() {
	ADD=$1
	PREFIX=""
	if ! test -z "${ADD}"; then
		PREFIX="$(echo $ADD|sed 's/://g'): "
	fi

	#AES-128-CCM
	for i in AES-128-GCM AES-256-GCM CHACHA20-POLY1305 AES-128-CCM AES-128-CCM-8;do
		echo_cmd "${PREFIX}Checking TLS 1.3 with ${i}..."

		eval "${GETPORT}"
		launch_server $$ --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+${i}${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" >>${OUTPUT} 2>&1
		PID=$!
		wait_server ${PID}

		${OPENSSL_CLI} s_client -ciphersuites ${OCIPHERSUITES} -host localhost -port "${PORT}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
			fail ${PID} "Failed"

		kill ${PID}
		wait
	done

	for i in GROUP-X25519 GROUP-SECP256R1 GROUP-SECP384R1 GROUP-SECP521R1;do
		echo_cmd "${PREFIX}Checking TLS 1.3 with ${i}..."

		eval "${GETPORT}"
		launch_server $$ --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+${i}${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
		PID=$!
		wait_server ${PID}

		${OPENSSL_CLI} s_client -host localhost -port "${PORT}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
			fail ${PID} "Failed"

		kill ${PID}
		wait
	done

	echo_cmd "${PREFIX}Checking TLS 1.3 with HRR..."
	eval "${GETPORT}"
	launch_server $$ --echo --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-SECP384R1${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
	PID=$!
	wait_server ${PID}

	${OPENSSL_CLI} s_client -groups 'X25519:P-256:X448:P-521:P-384' -host localhost -port "${PORT}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	echo_cmd "${PREFIX}Checking TLS 1.3 with rekey..."
	expect - >/dev/null <<_EOF_
set timeout 10
set os_error_flag 1
spawn ${OPENSSL_CLI} s_client -host localhost -port "${PORT}" -CAfile "${CA_CERT}"

expect "SSL-Session" {send "K\n"} timeout {exit 1}
expect "KEYUPDATE" {send "HELLO\n"} timeout {exit 1}
expect "HELLO" {close} timeout {exit 1}

lassign [wait] pid spawnid os_error_flag value
if {\$os_error_flag == 0} {
    exit $value
} else {
    exit 1
}
_EOF_
	if test $? != 0;then
		fail ${PID} "Failed"
	fi

	kill ${PID}
	wait

	# client certificates

	eval "${GETPORT}"
	launch_server $$ --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --require-client-cert --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" >>${OUTPUT} 2>&1
	PID=$!
	wait_server ${PID}

	echo_cmd "${PREFIX}Checking TLS 1.3 with RSA client certificate..."
	${OPENSSL_CLI} s_client -host localhost -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	echo_cmd "${PREFIX}Checking TLS 1.3 with RSA-PSS client certificate..."
	${OPENSSL_CLI} s_client -host localhost -port "${PORT}" -cert "${RSA_PSS_CLI_CERT}" -key "${RSA_PSS_CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	echo_cmd "${PREFIX}Checking TLS 1.3 with secp256r1 client certificate..."
	${OPENSSL_CLI} s_client -host localhost -port "${PORT}" -cert "${ECC_CLI_CERT}" -key "${ECC_CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	echo_cmd "${PREFIX}Checking TLS 1.3 with Ed25519 client certificate..."
	${OPENSSL_CLI} s_client -host localhost -port "${PORT}" -cert "${ED25519_CLI_CERT}" -key "${ED25519_CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	echo_cmd "${PREFIX}Checking TLS 1.3 with post handshake auth..."

	eval "${GETPORT}"
	launch_server $$ --echo --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" #>>${OUTPUT} 2>&1
	PID=$!
	wait_server ${PID}

	expect - >/dev/null <<_EOF_
set timeout 10
set os_error_flag 1
spawn ${OPENSSL_CLI} s_client -force_pha -host localhost -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}"

expect "SSL-Session" {send "**REAUTH**\n"} timeout {exit 1}
expect {
  timeout {exit 1}
  "error*" {exit 1}
  "Successfully executed command" {send "**REAUTH**\n"}
}
expect {
  timeout {exit 1}
  "error*" {exit 1}
  "Successfully executed command" {send "HELLO\n"}
}

expect "HELLO" {close} timeout {exit 1}

lassign [wait] pid spawnid os_error_flag value
if {\$os_error_flag == 0} {
    exit $value
} else {
    exit 1
}
_EOF_
	if test $? != 0;then
		fail ${PID} "Failed"
	fi

	kill ${PID}
	wait


	echo_cmd "${PREFIX}Checking TLS 1.3 with Ed25519 certificate..."

	eval "${GETPORT}"
	launch_server $$ --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509certfile "${ED25519_CERT}" --x509keyfile "${ED25519_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
	PID=$!
	wait_server ${PID}

	${OPENSSL_CLI} s_client -host localhost -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	echo_cmd "${PREFIX}Checking TLS 1.3 with secp256r1 certificate..."

	eval "${GETPORT}"
	launch_server $$ --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509certfile "${ECC_CERT}" --x509keyfile "${ECC_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
	PID=$!
	wait_server ${PID}

	${OPENSSL_CLI} s_client -host localhost -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	echo_cmd "${PREFIX}Checking TLS 1.3 with RSA-PSS certificate..."

	eval "${GETPORT}"
	launch_server $$ --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509certfile "${RSA_PSS_CERT}" --x509keyfile "${RSA_PSS_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
	PID=$!
	wait_server ${PID}

	${OPENSSL_CLI} s_client -host localhost -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait


	# openssl doesn't support PSK
	for i in DHE-PSK;do
		echo_cmd "${PREFIX}Checking TLS 1.3 with ${i}..."

		eval "${GETPORT}"
		launch_server $$ --pskpasswd "${SERV_PSK}" --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+${i}${ADD}" --x509cafile "${CA_CERT}" >>${OUTPUT} 2>&1
		PID=$!
		wait_server ${PID}

		${OPENSSL_CLI} s_client -host localhost -port "${PORT}" -psk_identity "${PSKID}" -psk "${PSKKEY}" </dev/null >>${OUTPUT} || \
			fail ${PID} "Failed"

		kill ${PID}
		wait
	done

	# Try resumption
	echo_cmd "${PREFIX}Checking TLS 1.3 with resumption..."
	testdir=`create_testdir tls13-openssl-resumption`
	eval "${GETPORT}"
	launch_server $$ --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509certfile "${RSA_CERT}" --x509keyfile "${RSA_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
	PID=$!
	wait_server ${PID}

	{ echo a; sleep 1; } | \
	${OPENSSL_CLI} s_client -host localhost -port "${PORT}" -CAfile "${CA_CERT}" -sess_out "${testdir}/sess.pem" 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"
	${OPENSSL_CLI} s_client -host localhost -port "${PORT}" -CAfile "${CA_CERT}" -sess_in "${testdir}/sess.pem" </dev/null 2>&1 > "${testdir}/server.out"
	grep "\:error\:" "${testdir}/server.out" && \
		fail ${PID} "Failed"
	grep "^Reused, TLSv1.3" "${testdir}/server.out" || \
		fail ${PID} "Failed"

	kill ${PID}
	wait
	rm -rf "$testdir"

}

run_server_suite

exit 0
