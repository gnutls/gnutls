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

: ${srcdir=.}
: ${SERV=../../src/gnutls-serv${EXEEXT}}
: ${CLI=../../src/gnutls-cli${EXEEXT}}
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

. "${srcdir}/testcompat-common"

: ${PORT=${RPORT}}

: ${OPENSSL=openssl}

if test -z "$OUTPUT";then
OUTPUT=/dev/null
fi

>${OUTPUT}

echo_cmd() {
	tee -a ${OUTPUT} <<<$(echo $1)
}

echo_cmd "Compatibility checks using "`${OPENSSL} version`

echo_cmd "#################################################"
echo_cmd "# Client mode tests (gnutls cli-openssl server) #"
echo_cmd "#################################################"

OCIPHERSUITES="TLS_AES_128_CCM_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_8_SHA256"

echo_cmd "${PREFIX}###############################################"
echo_cmd "${PREFIX}# Server mode tests (gnutls server-openssl cli#"
echo_cmd "${PREFIX}###############################################"
SERV="${SERV} -q"

# Note that openssl s_client does not return error code on failure

ADD=$1
PREFIX=""
if ! test -z "${ADD}"; then
	PREFIX="$(echo $ADD|sed 's/://g'): "
fi

#AES-128-CCM
for i in AES-128-GCM AES-256-GCM CHACHA20-POLY1305 AES-128-CCM AES-128-CCM-8;do
	echo_cmd "${PREFIX}Checking TLS 1.3 with cipher ${i}..."

	eval "${GETPORT}"
	launch_server --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+${i}${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" >>${OUTPUT} 2>&1
	PID=$!
	wait_server ${PID}

	${OPENSSL} s_client -ciphersuites ${OCIPHERSUITES} -host localhost -port "${PORT}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait
done

for i in GROUP-X25519 GROUP-X448 GROUP-SECP256R1 GROUP-SECP384R1 GROUP-SECP521R1;do
	echo_cmd "${PREFIX}Checking TLS 1.3 with group ${i}..."

	eval "${GETPORT}"
	launch_server --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+${i}${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
	PID=$!
	wait_server ${PID}

	${OPENSSL} s_client -host localhost -port "${PORT}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait
done

echo_cmd "${PREFIX}Checking TLS 1.3 with HRR..."
eval "${GETPORT}"
launch_server --echo --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-SECP384R1${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
PID=$!
wait_server ${PID}

${OPENSSL} s_client -groups 'X25519:P-256:X448:P-521:P-384' -host localhost -port "${PORT}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

echo_cmd "${PREFIX}Checking TLS 1.3 with rekey..."
expect - >/dev/null <<_EOF_
set timeout 10
set os_error_flag 1
spawn ${OPENSSL} s_client -host localhost -port "${PORT}" -CAfile "${CA_CERT}"

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
launch_server --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --require-client-cert --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" >>${OUTPUT} 2>&1
PID=$!
wait_server ${PID}

echo_cmd "${PREFIX}Checking TLS 1.3 with RSA client certificate..."
${OPENSSL} s_client -host localhost -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

echo_cmd "${PREFIX}Checking TLS 1.3 with RSA-PSS client certificate..."
${OPENSSL} s_client -host localhost -port "${PORT}" -cert "${RSA_PSS_CLI_CERT}" -key "${RSA_PSS_CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

echo_cmd "${PREFIX}Checking TLS 1.3 with secp256r1 client certificate..."
${OPENSSL} s_client -host localhost -port "${PORT}" -cert "${ECC_CLI_CERT}" -key "${ECC_CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

echo_cmd "${PREFIX}Checking TLS 1.3 with Ed25519 client certificate..."
${OPENSSL} s_client -host localhost -port "${PORT}" -cert "${ED25519_CLI_CERT}" -key "${ED25519_CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

echo_cmd "${PREFIX}Checking TLS 1.3 with Ed448 client certificate..."
${OPENSSL} s_client -host localhost -port "${PORT}" -cert "${ED448_CLI_CERT}" -key "${ED448_CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait

echo_cmd "${PREFIX}Checking TLS 1.3 with post handshake auth..."

eval "${GETPORT}"
launch_server --echo --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" >>${OUTPUT} 2>&1
PID=$!
wait_server ${PID}

expect - >/dev/null <<_EOF_
set timeout 10
set os_error_flag 1
spawn ${OPENSSL} s_client -enable_pha -host localhost -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}"

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
launch_server --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509certfile "${ED25519_CERT}" --x509keyfile "${ED25519_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
PID=$!
wait_server ${PID}

${OPENSSL} s_client -host localhost -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait

echo_cmd "${PREFIX}Checking TLS 1.3 with Ed448 certificate..."

eval "${GETPORT}"
launch_server --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509certfile "${ED448_CERT}" --x509keyfile "${ED448_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
PID=$!
wait_server ${PID}

${OPENSSL} s_client -host localhost -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait

echo_cmd "${PREFIX}Checking TLS 1.3 with secp256r1 certificate..."

eval "${GETPORT}"
launch_server --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509certfile "${ECC_CERT}" --x509keyfile "${ECC_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
PID=$!
wait_server ${PID}

${OPENSSL} s_client -host localhost -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait

echo_cmd "${PREFIX}Checking TLS 1.3 with RSA-PSS certificate..."

eval "${GETPORT}"
launch_server --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509certfile "${RSA_PSS_CERT}" --x509keyfile "${RSA_PSS_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
PID=$!
wait_server ${PID}

${OPENSSL} s_client -host localhost -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait


# openssl doesn't support PSK
for i in DHE-PSK;do
	echo_cmd "${PREFIX}Checking TLS 1.3 with ${i}..."

	eval "${GETPORT}"
	launch_server --pskpasswd "${SERV_PSK}" --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+${i}${ADD}" --x509cafile "${CA_CERT}" >>${OUTPUT} 2>&1
	PID=$!
	wait_server ${PID}

	${OPENSSL} s_client -host localhost -port "${PORT}" -psk_identity "${PSKID}" -psk "${PSKKEY}" </dev/null >>${OUTPUT} || \
		fail ${PID} "Failed"

	kill ${PID}
	wait
done

# Try resumption
echo_cmd "${PREFIX}Checking TLS 1.3 with resumption..."
testdir=`create_testdir tls13-openssl-resumption`
eval "${GETPORT}"
launch_server --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509certfile "${RSA_CERT}" --x509keyfile "${RSA_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
PID=$!
wait_server ${PID}

{ echo a; sleep 1; } | \
${OPENSSL} s_client -host localhost -port "${PORT}" -CAfile "${CA_CERT}" -sess_out "${testdir}/sess.pem" 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"
${OPENSSL} s_client -host localhost -port "${PORT}" -CAfile "${CA_CERT}" -sess_in "${testdir}/sess.pem" </dev/null 2>&1 > "${testdir}/server.out"
grep "\:error\:" "${testdir}/server.out" && \
	fail ${PID} "Failed"
grep "^Reused, TLSv1.3" "${testdir}/server.out" || \
	fail ${PID} "Failed"

kill ${PID}
wait

echo_cmd "${PREFIX}Checking TLS 1.3 with resumption and HRR..."
eval "${GETPORT}"
launch_server --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-256-GCM:-GROUP-ALL:+GROUP-SECP384R1${ADD}" --x509certfile "${RSA_CERT}" --x509keyfile "${RSA_KEY}" --x509cafile "${CA_CERT}"  >>${OUTPUT} 2>&1
PID=$!
wait_server ${PID}

{ echo a; sleep 1; } | \
${OPENSSL} s_client -host localhost -port "${PORT}" -curves 'X25519:P-256:X448:P-521:P-384' -CAfile "${CA_CERT}" -sess_out "${testdir}/sess-hrr.pem" 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"
${OPENSSL} s_client -host localhost -port "${PORT}" -curves 'X25519:P-256:X448:P-521:P-384' -CAfile "${CA_CERT}" -sess_in "${testdir}/sess-hrr.pem" </dev/null 2>&1 > "${testdir}/server.out"
grep "\:error\:" "${testdir}/server.out" && \
	fail ${PID} "Failed"
grep "^Reused, TLSv1.3" "${testdir}/server.out" || \
	fail ${PID} "Failed"

kill ${PID}
wait

echo_cmd "${PREFIX}Checking TLS 1.3 with resumption and early data..."
testdir=`create_testdir tls13-openssl-resumption`
eval "${GETPORT}"
launch_server --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509certfile "${RSA_CERT}" --x509keyfile "${RSA_KEY}" --x509cafile "${CA_CERT}" --earlydata  >>${OUTPUT} 2>&1
PID=$!
wait_server ${PID}

echo "This file contains early data sent by the client" > "${testdir}/earlydata.txt"
{ echo a; sleep 1; } | \
${OPENSSL} s_client -host localhost -port "${PORT}" -CAfile "${CA_CERT}" -sess_out "${testdir}/sess-earlydata.pem" 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"
${OPENSSL} s_client -host localhost -port "${PORT}" -CAfile "${CA_CERT}" -sess_in "${testdir}/sess-earlydata.pem" -early_data "${testdir}/earlydata.txt" </dev/null 2>&1 > "${testdir}/server.out"
grep "\:error\:" "${testdir}/server.out" && \
	fail ${PID} "Failed"
grep "^Reused, TLSv1.3" "${testdir}/server.out" || \
	fail ${PID} "Failed"

kill ${PID}
wait

echo_cmd "${PREFIX}Checking TLS 1.3 with resumption and early data with small limit..."
testdir=`create_testdir tls13-openssl-resumption`
eval "${GETPORT}"
launch_server --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3${ADD}" --x509certfile "${RSA_CERT}" --x509keyfile "${RSA_KEY}" --x509cafile "${CA_CERT}" --earlydata --maxearlydata 1  >>${OUTPUT} 2>&1
PID=$!
wait_server ${PID}

echo "This file contains early data sent by the client" > "${testdir}/earlydata.txt"
{ echo a; sleep 1; } | \
${OPENSSL} s_client -host localhost -port "${PORT}" -CAfile "${CA_CERT}" -sess_out "${testdir}/sess-earlydata.pem" 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"
${OPENSSL} s_client -host localhost -port "${PORT}" -CAfile "${CA_CERT}" -sess_in "${testdir}/sess-earlydata.pem" -early_data "${testdir}/earlydata.txt" </dev/null 2>&1 > "${testdir}/server.out"
grep "^Early data was rejected" "${testdir}/server.out" || \
	fail ${PID} "Failed"

kill ${PID}
wait
rm -rf "${testdir}"
