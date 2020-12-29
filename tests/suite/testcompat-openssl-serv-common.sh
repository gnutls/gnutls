#!/bin/sh

# Copyright (c) 2010-2016, Free Software Foundation, Inc.
# Copyright (c) 2012-2016, Nikos Mavrogiannopoulos
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

: ${PORT=${RPORT}}

: ${OPENSSL=openssl}
SIGALGS=RSA+SHA1:RSA+SHA256

echo "Compatibility checks using "`${OPENSSL} version`
${OPENSSL} version|grep -e '1\.[0-9]\..' >/dev/null 2>&1
if test $? != 0; then
	echo "OpenSSL 1.0.0 is required for ECDH and DTLS tests"
	exit 77
fi

. "${srcdir}/testcompat-common"

${OPENSSL} version|grep -e '1\.[1-9]\..' >/dev/null 2>&1
HAVE_X25519=$?

test $HAVE_X25519 != 0 && echo "Disabling interop tests for x25519"

${OPENSSL} version|grep -e '[1-9]\.[0-9]\.[0-9]' >/dev/null 2>&1
NO_TLS1_2=$?

test $NO_TLS1_2 != 0 && echo "Disabling interop tests for TLS 1.2"

${OPENSSL} version|grep -e '[1-9]\.[1-9]\.[0-9]' >/dev/null 2>&1
if test $? = 0;then
	NO_DH_PARAMS=0
else
	NO_DH_PARAMS=1
fi

${OPENSSL} ciphers -v ALL 2>&1|grep -e DHE-DSS >/dev/null 2>&1
NO_DSS=$?

if test $NO_DSS != 0;then
	echo "Disabling interop tests for DSS ciphersuites"
else
	DSA_PARAMS="-dkey ${DSA_KEY} -dcert ${DSA_CERT}"
	SIGALGS="$SIGALGS:DSA+SHA1:DSA+SHA256"
fi

${OPENSSL} ciphers -v ALL 2>&1|grep -e CAMELLIA >/dev/null 2>&1
NO_CAMELLIA=$?

test $NO_CAMELLIA != 0 && echo "Disabling interop tests for Camellia ciphersuites"

${OPENSSL} ciphers -v ALL 2>&1|grep -e RC4 >/dev/null 2>&1
NO_RC4=$?

test $NO_RC4 != 0 && echo "Disabling interop tests for RC4 ciphersuites"

${OPENSSL} ciphers -v ALL 2>&1|grep -e 3DES >/dev/null 2>&1
NO_3DES=$?

test $NO_3DES != 0 && echo "Disabling interop tests for 3DES ciphersuites"

${OPENSSL} ciphers -v ALL 2>&1|grep -e NULL >/dev/null 2>&1
NO_NULL=$?

test $NO_NULL != 0 && echo "Disabling interop tests for NULL ciphersuites"

${OPENSSL} ecparam -list_curves 2>&1|grep -e prime192v1 >/dev/null 2>&1
NO_PRIME192v1=$?

test $NO_PRIME192v1 != 0 && echo "Disabling interop tests for prime192v1 ecparam"

if test "${NO_DH_PARAMS}" = 0;then
	OPENSSL_DH_PARAMS_OPT=""
else
	OPENSSL_DH_PARAMS_OPT="-dhparam \"${DH_PARAMS}\""
fi

${OPENSSL} s_server -help 2>&1|grep -e -ssl3 >/dev/null 2>&1
HAVE_NOT_SSL3=$?

if test $HAVE_NOT_SSL3 = 0;then
	eval "${GETPORT}"
	launch_bare_server "$OPENSSL" s_server -cipher ALL -quiet -www -accept "${PORT}" -keyform pem -certform pem -ssl3 -key "${RSA_KEY}" -cert "${RSA_CERT}" >/dev/null 2>&1
	PID=$!
	wait_server ${PID}

	${OPENSSL} s_client -host localhost -port "${PORT}" -ssl3 </dev/null 2>&1 | grep "\:error\:" && \
		HAVE_NOT_SSL3=1
	kill ${PID}
	wait
fi

test $HAVE_NOT_SSL3 != 0 && echo "Disabling interop tests for SSL 3.0"


echo "${PREFIX}###############################################"
echo "${PREFIX}# Server mode tests (gnutls server-openssl cli#"
echo "${PREFIX}###############################################"
SERV="${SERV} -q"

# Note that openssl s_client does not return error code on failure

ADD=$1
PREFIX=""
if ! test -z "${ADD}"; then
	PREFIX="$(echo $ADD|sed 's/://g'): "
fi

if test "${HAVE_NOT_SSL3}" != 1 && test "${ENABLE_SSL3}" = 1; then

	echo "${PREFIX}Check SSL 3.0 with RSA ciphersuite"
	eval "${GETPORT}"
	launch_server --priority "NONE:+SHA1:+ARCFOUR-128:+3DES-CBC:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-SSL3.0:+RSA${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" --dhparams "${DH_PARAMS}"
	PID=$!
	wait_server ${PID}

	${OPENSSL} s_client -host localhost -port "${PORT}" -ssl3 -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	if test "${NO_RC4}" != 1; then
		echo "${PREFIX}Check SSL 3.0 with RSA-RC4-SHA ciphersuite"
		${OPENSSL} s_client -host localhost -port "${PORT}" -ssl3 -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" -cipher RC4-SHA </dev/null 2>&1 | grep "\:error\:" && \
			fail ${PID} "Failed"
	fi

	kill ${PID}
	wait

	echo "${PREFIX}Check SSL 3.0 with DHE-RSA ciphersuite"
	eval "${GETPORT}"
	launch_server --priority "NONE:+CIPHER-ALL:+3DES-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-SSL3.0:+DHE-RSA${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" --dhparams "${DH_PARAMS}"
	PID=$!
	wait_server ${PID}

	${OPENSSL} s_client -cipher DHE -host localhost -port "${PORT}" -ssl3 -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	if test "${NO_DSS}" = 0; then
		echo "${PREFIX}Check SSL 3.0 with DHE-DSS ciphersuite"
		eval "${GETPORT}"
		launch_server --priority "NONE:+CIPHER-ALL:+3DES-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-SSL3.0:+DHE-DSS:+SIGN-DSA-SHA1:+SIGN-DSA-SHA256${ADD}" --x509certfile "${SERV_DSA_CERT}" --x509keyfile "${SERV_DSA_KEY}" --dhparams "${DH_PARAMS}"
		PID=$!
		wait_server ${PID}

		${OPENSSL} s_client -cipher DHE -host localhost -port "${PORT}" -ssl3 -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
			fail ${PID} "Failed"

		kill ${PID}
		wait
	fi
fi

#TLS 1.0

# This test was disabled because it doesn't work as expected with openssl 1.0.0d
#echo "${PREFIX}Check TLS 1.0 with RSA ciphersuite (SSLv2 hello)"
#launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+RSA" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" --dhparams "${DH_PARAMS}"
#PID=$!
#wait_server ${PID}
#
#${OPENSSL} s_client -host localhost -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
#	fail ${PID} "Failed"
#
#kill ${PID}
#wait

if test "${NO_NULL}" = 0; then
	echo "${PREFIX}Check TLS 1.0 with RSA-NULL ciphersuite"
	eval "${GETPORT}"
	launch_server --priority "NONE:+NULL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+RSA:+DHE-RSA${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" --dhparams "${DH_PARAMS}"
	PID=$!
	wait_server ${PID}

	${OPENSSL} s_client -cipher NULL-SHA -host localhost -tls1 -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait
fi

echo "${PREFIX}Check TLS 1.0 with DHE-RSA ciphersuite"
eval "${GETPORT}"
launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+DHE-RSA${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" --dhparams "${DH_PARAMS}"
PID=$!
wait_server ${PID}

${OPENSSL} s_client -cipher DHE:@SECLEVEL=1 -host localhost -tls1 -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait

if test "${NO_DSS}" = 0; then
	echo "${PREFIX}Check TLS 1.0 with DHE-DSS ciphersuite"
	eval "${GETPORT}"
	launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+DHE-DSS:+SIGN-DSA-SHA1:+SIGN-DSA-SHA256${ADD}" --x509certfile "${SERV_DSA_CERT}" --x509keyfile "${SERV_DSA_KEY}" --dhparams "${DH_PARAMS}"
	PID=$!
	wait_server ${PID}

	${OPENSSL} s_client -host localhost -cipher ALL:@SECLEVEL=1 -sigalgs "$SIGALGS" -tls1 -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait
fi

echo "${PREFIX}Check TLS 1.0 with ECDHE-RSA ciphersuite"
eval "${GETPORT}"
launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+ECDHE-RSA:+CURVE-ALL${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}"
PID=$!
wait_server ${PID}

#-cipher ECDHE-RSA-AES128-SHA
${OPENSSL} s_client -host localhost -cipher ALL:@SECLEVEL=1 -tls1 -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait

if test "${FIPS_CURVES}" != 1; then
	echo "${PREFIX}Check TLS 1.0 with ECDHE-ECDSA ciphersuite (SECP224R1)"
	eval "${GETPORT}"
	launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+ECDHE-ECDSA:+CURVE-SECP224R1:+CURVE-ALL${ADD}" --x509certfile "${ECC224_CERT}" --x509keyfile "${ECC224_KEY}" --x509cafile "${CA_ECC_CERT}"
	PID=$!
	wait_server ${PID}

	#-cipher ECDHE-ECDSA-AES128-SHA
	${OPENSSL} s_client -host localhost -cipher ALL:@SECLEVEL=1 -tls1 -named_curve secp224r1 -port "${PORT}" -cert "${ECC224_CERT}" -key "${ECC224_KEY}" -CAfile "${CA_ECC_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait
fi

echo "${PREFIX}Check TLS 1.0 with ECDHE-ECDSA ciphersuite (SECP256R1)"
eval "${GETPORT}"
launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+ECDHE-ECDSA:+CURVE-ALL${ADD}" --x509certfile "${ECC256_CERT}" --x509keyfile "${ECC256_KEY}" --x509cafile "${CA_ECC_CERT}"
PID=$!
wait_server ${PID}

#-cipher ECDHE-ECDSA-AES128-SHA
${OPENSSL} s_client -host localhost -cipher ALL:@SECLEVEL=1 -tls1 -port "${PORT}" -cert "${ECC256_CERT}" -key "${ECC256_KEY}" -CAfile "${CA_ECC_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait

echo "${PREFIX}Check TLS 1.0 with ECDHE-ECDSA ciphersuite (SECP384R1)"
eval "${GETPORT}"
launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+ECDHE-ECDSA:+CURVE-ALL${ADD}" --x509certfile "${ECC384_CERT}" --x509keyfile "${ECC384_KEY}" --x509cafile "${CA_ECC_CERT}"
PID=$!
wait_server ${PID}

#-cipher ECDHE-ECDSA-AES128-SHA
${OPENSSL} s_client -host localhost -cipher ALL:@SECLEVEL=1 -tls1 -port "${PORT}" -cert "${ECC384_CERT}" -key "${ECC384_KEY}" -CAfile "${CA_ECC_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait

if test "${FIPS_CURVES}" != 1; then
	echo "${PREFIX}Check TLS 1.0 with ECDHE-ECDSA ciphersuite (SECP521R1)"
	eval "${GETPORT}"
	launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+ECDHE-ECDSA:+CURVE-ALL${ADD}" --x509certfile "${ECC521_CERT}" --x509keyfile "${ECC521_KEY}" --x509cafile "${CA_ECC_CERT}"
	PID=$!
	wait_server ${PID}

	#-cipher ECDHE-ECDSA-AES128-SHA
	${OPENSSL} s_client -host localhost -cipher ALL:@SECLEVEL=1 -tls1 -port "${PORT}" -cert "${ECC521_CERT}" -key "${ECC521_KEY}" -CAfile "${CA_ECC_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait
fi

echo "${PREFIX}Check TLS 1.0 with PSK ciphersuite"
eval "${GETPORT}"
launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+PSK:+CURVE-ALL${ADD}" --pskpasswd "${SERV_PSK}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}"
PID=$!
wait_server ${PID}

#-cipher PSK-AES128-SHA
${OPENSSL} s_client -host localhost -psk_identity Client_identity -psk 9e32cf7786321a828ef7668f09fb35db -cipher ALL:@SECLEVEL=1 -tls1 -port "${PORT}" crt_file="${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep ":error:" && \
	fail ${PID} "Failed"

kill ${PID}
wait

if test ${NO_TLS1_2} = 0; then
	# test resumption
	echo "${PREFIX}Check TLS 1.2 with resumption"
	eval "${GETPORT}"
	launch_server --priority "NORMAL${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}"
	PID=$!
	wait_server ${PID}

	${OPENSSL} s_client -host localhost -reconnect -tls1_2 -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	echo "${PREFIX}Check TLS 1.2 with DHE-RSA ciphersuite"
	eval "${GETPORT}"
	launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+DHE-RSA${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" --dhparams "${DH_PARAMS}"
	PID=$!
	wait_server ${PID}

	${OPENSSL} s_client -cipher DHE -host localhost -tls1_2 -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	if test "${NO_DSS}" = 0; then
		echo "${PREFIX}Check TLS 1.2 with DHE-DSS ciphersuite"
		eval "${GETPORT}"
		launch_server --priority "NONE:+CIPHER-ALL:%VERIFY_ALLOW_SIGN_WITH_SHA1:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+DHE-DSS:+SIGN-DSA-SHA1:+SIGN-DSA-SHA256${ADD}" --x509certfile "${SERV_DSA_CERT}" --x509keyfile "${SERV_DSA_KEY}" --dhparams "${DH_PARAMS}"
		PID=$!
		wait_server ${PID}

		${OPENSSL} s_client -cipher DHE -host localhost -cipher 'ALL:@SECLEVEL=1' -sigalgs "$SIGALGS" -tls1_2 -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
			fail ${PID} "Failed"

		kill ${PID}
		wait
	fi

	echo "${PREFIX}Check TLS 1.2 with ECDHE-RSA ciphersuite"
	eval "${GETPORT}"
	launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+ECDHE-RSA:+CURVE-ALL${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}"
	PID=$!
	wait_server ${PID}

	#-cipher ECDHE-RSA-AES128-SHA
	${OPENSSL} s_client -host localhost -tls1_2 -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	if test "${HAVE_X22519}" = 0; then
		echo "${PREFIX}Check TLS 1.2 with ECDHE-RSA ciphersuite (X25519)"
		eval "${GETPORT}"
		launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+ECDHE-RSA:+CURVE-X25519${ADD}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}"
		PID=$!
		wait_server ${PID}

		${OPENSSL} s_client -host localhost -tls1_2 -port "${PORT}" -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
			fail ${PID} "Failed"

		kill ${PID}
		wait
	fi

	if test "${FIPS_CURVES}" != 1; then
		echo "${PREFIX}Check TLS 1.2 with ECDHE-ECDSA ciphersuite (SECP224R1)"
		eval "${GETPORT}"
		launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+ECDHE-ECDSA:+CURVE-SECP224R1:+CURVE-ALL${ADD}" --x509certfile "${ECC224_CERT}" --x509keyfile "${ECC224_KEY}" --x509cafile "${CA_ECC_CERT}"
		PID=$!
		wait_server ${PID}

		#-cipher ECDHE-ECDSA-AES128-SHA
		${OPENSSL} s_client -host localhost -cipher 'ALL:@SECLEVEL=1' -tls1_2 -named_curve secp224r1 -port "${PORT}" -cert "${ECC224_CERT}" -key "${ECC224_KEY}" -CAfile "${CA_ECC_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
			fail ${PID} "Failed"

		kill ${PID}
		wait
	fi

	echo "${PREFIX}Check TLS 1.2 with ECDHE-ECDSA ciphersuite (SECP256R1)"
	eval "${GETPORT}"
	launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+ECDHE-ECDSA:+CURVE-ALL${ADD}" --x509certfile "${ECC256_CERT}" --x509keyfile "${ECC256_KEY}" --x509cafile "${CA_ECC_CERT}"
	PID=$!
	wait_server ${PID}

	#-cipher ECDHE-ECDSA-AES128-SHA
	${OPENSSL} s_client -host localhost -tls1_2 -port "${PORT}" -cert "${ECC256_CERT}" -key "${ECC256_KEY}" -CAfile "${CA_ECC_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	echo "${PREFIX}Check TLS 1.2 with ECDHE-ECDSA ciphersuite (SECP384R1)"
	eval "${GETPORT}"
	launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+ECDHE-ECDSA:+CURVE-ALL${ADD}" --x509certfile "${ECC384_CERT}" --x509keyfile "${ECC384_KEY}" --x509cafile "${CA_ECC_CERT}"
	PID=$!
	wait_server ${PID}

	#-cipher ECDHE-ECDSA-AES128-SHA
	${OPENSSL} s_client -host localhost -tls1_2 -port "${PORT}" -cert "${ECC384_CERT}" -key "${ECC384_KEY}" -CAfile "${CA_ECC_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	if test "${FIPS_CURVES}" != 1; then
		echo "${PREFIX}Check TLS 1.2 with ECDHE-ECDSA ciphersuite (SECP521R1)"
		eval "${GETPORT}"
		launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+ECDHE-ECDSA:+CURVE-ALL${ADD}" --x509certfile "${ECC521_CERT}" --x509keyfile "${ECC521_KEY}" --x509cafile "${CA_ECC_CERT}"
		PID=$!
		wait_server ${PID}

		#-cipher ECDHE-ECDSA-AES128-SHA
		${OPENSSL} s_client -host localhost -tls1_2 -port "${PORT}" -cert "${ECC521_CERT}" -key "${ECC521_KEY}" -CAfile "${CA_ECC_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
			fail ${PID} "Failed"

		kill ${PID}
		wait
	fi

	echo "${PREFIX}Check TLS 1.2 with PSK ciphersuite"
	eval "${GETPORT}"
	launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+PSK:+CURVE-ALL${ADD}" --pskpasswd "${SERV_PSK}" --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}"
	PID=$!
	wait_server ${PID}

	#-cipher PSK-AES128-SHA
	${OPENSSL} s_client -host localhost -psk_identity Client_identity -psk 9e32cf7786321a828ef7668f09fb35db -tls1_2 -port "${PORT}" crt_file="${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep ":error:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait

fi #NO_TLS1_2

# DTLS
echo "${PREFIX}Check DTLS 1.0 with RSA ciphersuite"
eval "${GETPORT}"
launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-DTLS1.0:+RSA${ADD}" --udp --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" --dhparams "${DH_PARAMS}"
PID=$!
wait_udp_server ${PID}

${OPENSSL} s_client -host localhost -port "${PORT}" -cipher 'ALL:@SECLEVEL=1' -dtls1 -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait


echo "${PREFIX}Check DTLS 1.0 with DHE-RSA ciphersuite"
eval "${GETPORT}"
launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-DTLS1.0:+DHE-RSA${ADD}" --udp --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" --dhparams "${DH_PARAMS}"
PID=$!
wait_udp_server ${PID}


${OPENSSL} s_client -cipher DHE -host localhost -port "${PORT}" -cipher 'ALL:@SECLEVEL=1' -dtls1 -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait

if test "${NO_DSS}" = 0; then
	echo "${PREFIX}Check DTLS 1.0 with DHE-DSS ciphersuite"
	eval "${GETPORT}"
	launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-DTLS1.0:+DHE-DSS:+SIGN-DSA-SHA1:+SIGN-DSA-SHA256${ADD}" --udp --x509certfile "${SERV_DSA_CERT}" --x509keyfile "${SERV_DSA_KEY}" --dhparams "${DH_PARAMS}"
	PID=$!
	wait_udp_server ${PID}


	${OPENSSL} s_client -host localhost -port "${PORT}" -cipher 'ALL:@SECLEVEL=1' -sigalgs "$SIGALGS" -dtls1 -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
		fail ${PID} "Failed"

	kill ${PID}
	wait
fi

echo "${PREFIX}Check DTLS 1.2 with AES-CBC"
eval "${GETPORT}"
launch_server --priority "NONE:+AES-128-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-DTLS1.2:+RSA${ADD}" --udp --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" --dhparams "${DH_PARAMS}"
PID=$!
wait_udp_server ${PID}

${OPENSSL} s_client -host localhost -port "${PORT}" -dtls1_2 -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait

echo "${PREFIX}Check DTLS 1.2 with RSA ciphersuite"
eval "${GETPORT}"
launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-DTLS1.2:+RSA${ADD}" --udp --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" --dhparams "${DH_PARAMS}"
PID=$!
wait_udp_server ${PID}

${OPENSSL} s_client -host localhost -port "${PORT}" -dtls1_2 -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait


echo "${PREFIX}Check DTLS 1.2 with DHE-RSA ciphersuite"
eval "${GETPORT}"
launch_server --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-DTLS1.2:+DHE-RSA${ADD}" --udp --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}" --dhparams "${DH_PARAMS}"
PID=$!
wait_udp_server ${PID}


${OPENSSL} s_client -cipher DHE -host localhost -port "${PORT}" -dtls1_2 -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait

echo "${PREFIX}Check DTLS 1.2 with ECDHE-RSA"
eval "${GETPORT}"
launch_server --priority "NONE:+GROUP-ALL:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-DTLS1.2:+ECDHE-RSA${ADD}" --udp --x509certfile "${SERV_CERT}" --x509keyfile "${SERV_KEY}" --x509cafile "${CA_CERT}"
PID=$!
wait_udp_server ${PID}


${OPENSSL} s_client -cipher ECDHE -host localhost -port "${PORT}" -dtls1_2 -cert "${CLI_CERT}" -key "${CLI_KEY}" -CAfile "${CA_CERT}" </dev/null 2>&1 | grep "\:error\:" && \
	fail ${PID} "Failed"

kill ${PID}
wait
