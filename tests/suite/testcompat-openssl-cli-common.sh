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


echo "#################################################"
echo "# Client mode tests (gnutls cli-openssl server) #"
echo "#################################################"

ADD=$1
PREFIX=""
if ! test -z "${ADD}"; then
	PREFIX="$(echo $ADD|sed 's/://g'): "
fi

if test "${HAVE_NOT_SSL3}" != 1 && test "${ENABLE_SSL3}" = 1; then
	# It seems debian disabled SSL 3.0 completely on openssl

	eval "${GETPORT}"
	launch_bare_server "$OPENSSL" s_server -cipher ALL -sigalgs "$SIGALGS" -quiet -www -accept "${PORT}" -keyform pem -certform pem -ssl3 ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" ${DSA_PARAMS} -Verify 1 -CAfile "${CA_CERT}" >/dev/null
	PID=$!
	wait_server ${PID}

	# Test SSL 3.0 with RSA ciphersuite
	echo "${PREFIX}Checking SSL 3.0 with RSA..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+3DES-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-SSL3.0:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	# Test SSL 3.0 with DHE-RSA ciphersuite
	echo "${PREFIX}Checking SSL 3.0 with DHE-RSA..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+3DES-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-SSL3.0:+DHE-RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	if test "${NO_DSS}" = 0; then
		# Test SSL 3.0 with DHE-DSS ciphersuite
		echo "${PREFIX}Checking SSL 3.0 with DHE-DSS..."
		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+3DES-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-SSL3.0:+DHE-DSS:+SIGN-DSA-SHA1:+SIGN-DSA-SHA256${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
			fail ${PID} "Failed"
	fi

	kill ${PID}
	wait

	if test "${NO_RC4}" != 1; then
		eval "${GETPORT}"
		launch_bare_server "$OPENSSL" s_server -quiet -www -accept "${PORT}" -keyform pem -certform pem -ssl3 ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" -cipher RC4-SHA >/dev/null
		PID=$!
		wait_server ${PID}

		echo "${PREFIX}Checking SSL 3.0 with RSA-RC4-SHA..."
		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+ARCFOUR-128:+SHA1:+SIGN-ALL:+COMP-NULL:+VERS-SSL3.0:+RSA${ADD}" --insecure </dev/null >/dev/null || \
			fail ${PID} "Failed"

		kill ${PID}
		wait
	fi
fi

if test "${NO_NULL}" = 0; then
	#-cipher RSA-NULL
	eval "${GETPORT}"
	launch_bare_server "$OPENSSL" s_server -cipher NULL-SHA -quiet -www -accept "${PORT}" -keyform pem -certform pem -tls1 ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" -Verify 1 -CAfile "${CA_CERT}" >/dev/null
	PID=$!
	wait_server ${PID}

	# Test TLS 1.0 with RSA-NULL ciphersuite
	echo "${PREFIX}Checking TLS 1.0 with RSA-NULL..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+NULL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	kill ${PID}
	wait
fi

#-cipher RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA
eval "${GETPORT}"
launch_bare_server "$OPENSSL" s_server -cipher "ALL:@SECLEVEL=1" -sigalgs "$SIGALGS" -quiet -www -accept "${PORT}" -keyform pem -certform pem -tls1 ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" ${DSA_PARAMS} -Verify 1 -CAfile "${CA_CERT}" >/dev/null
PID=$!
wait_server ${PID}

# Test TLS 1.0 with RSA ciphersuite
if test "${NO_3DES}" != 1; then
	echo "${PREFIX}Checking TLS 1.0 with RSA and 3DES-CBC..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+3DES-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"
fi

echo "${PREFIX}Checking TLS 1.0 with RSA and AES-128-CBC..."
${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-128-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
	fail ${PID} "Failed"

echo "${PREFIX}Checking TLS 1.0 with RSA and AES-256-CBC..."
${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-256-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
	fail ${PID} "Failed"

if test "${NO_CAMELLIA}" != 1; then
	echo "${PREFIX}Checking TLS 1.0 with RSA and CAMELLIA-128-CBC..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CAMELLIA-128-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.0 with RSA and CAMELLIA-256-CBC..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CAMELLIA-256-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"
fi

if test "${NO_DSS}" = 0; then
	# Test TLS 1.0 with DHE-DSS ciphersuite
	echo "${PREFIX}Checking TLS 1.0 with DHE-DSS..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+DHE-DSS:+SIGN-DSA-SHA1:+SIGN-DSA-SHA256${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"
fi

# Test TLS 1.0 with DHE-RSA ciphersuite
echo "${PREFIX}Checking TLS 1.0 with DHE-RSA..."
${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+DHE-RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
	fail ${PID} "Failed"

# Test TLS 1.0 with DHE-RSA ciphersuite
echo "${PREFIX}Checking TLS 1.0 with ECDHE-RSA..."
${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+ECDHE-RSA:+CURVE-ALL${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
	fail ${PID} "Failed"

kill ${PID}
wait

if test "${FIPS_CURVES}" != 1 && test "${NO_PRIME192v1}" != 1; then
	eval "${GETPORT}"
	launch_bare_server "$OPENSSL" s_server -quiet -www -accept "${PORT}" -keyform pem -certform pem -cipher 'DEFAULT:@SECLEVEL=1' -tls1 -key "${RSA_KEY}" -cert "${RSA_CERT}" -named_curve prime192v1 -CAfile "${CA_CERT}" >/dev/null
	PID=$!
	wait_server ${PID}

	# Test TLS 1.2 with ECDHE-ECDSA ciphersuite
	echo "${PREFIX}Checking TLS 1.0 with ECDHE-RSA (SECP192R1)..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+ECDHE-RSA:+CURVE-SECP192R1${ADD}" --insecure </dev/null >/dev/null || \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	#-cipher ECDHE-ECDSA-AES128-SHA
	eval "${GETPORT}"
	launch_bare_server "$OPENSSL" s_server -quiet -www -accept "${PORT}" -keyform pem -certform pem -cipher 'DEFAULT:@SECLEVEL=1' -tls1 -key "${ECC224_KEY}" -cert "${ECC224_CERT}" -Verify 1 -named_curve secp224r1 -CAfile "${CA_ECC_CERT}" >/dev/null
	PID=$!
	wait_server ${PID}

	# Test TLS 1.0 with ECDHE-ECDSA ciphersuite
	echo "${PREFIX}Checking TLS 1.0 with ECDHE-ECDSA (SECP224R1)..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+ECDHE-ECDSA:+CURVE-SECP224R1${ADD}" --insecure --x509certfile "${ECC224_CERT}" --x509keyfile "${ECC224_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	kill ${PID}
	wait
fi

#-cipher ECDHE-ECDSA-AES128-SHA
eval "${GETPORT}"
launch_bare_server "$OPENSSL" s_server -quiet -www -accept "${PORT}" -keyform pem -certform pem -cipher 'DEFAULT:@SECLEVEL=1' -tls1 -key "${ECC384_KEY}" -cert "${ECC384_CERT}" -Verify 1 -named_curve secp384r1 -CAfile "${CA_ECC_CERT}" >/dev/null
PID=$!
wait_server ${PID}

# Test TLS 1.0 with ECDHE-ECDSA ciphersuite
echo "${PREFIX}Checking TLS 1.0 with ECDHE-ECDSA (SECP384R1)..."
${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+ECDHE-ECDSA:+CURVE-ALL${ADD}" --insecure --x509certfile "${ECC384_CERT}" --x509keyfile "${ECC384_KEY}" </dev/null >/dev/null || \
	fail ${PID} "Failed"

kill ${PID}
wait

#-cipher ECDHE-ECDSA-AES128-SHA
eval "${GETPORT}"
launch_bare_server "$OPENSSL" s_server -quiet -www -accept "${PORT}" -keyform pem -certform pem -cipher 'DEFAULT:@SECLEVEL=1' -tls1 -key "${ECC521_KEY}" -cert "${ECC521_CERT}" -Verify 1 -named_curve secp521r1 -CAfile "${CA_ECC_CERT}" >/dev/null
PID=$!
wait_server ${PID}

# Test TLS 1.0 with ECDHE-ECDSA ciphersuite
echo "${PREFIX}Checking TLS 1.0 with ECDHE-ECDSA (SECP521R1)..."
${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+ECDHE-ECDSA:+CURVE-ALL${ADD}" --insecure --x509certfile "${ECC521_CERT}" --x509keyfile "${ECC521_KEY}" </dev/null >/dev/null || \
	fail ${PID} "Failed"

kill ${PID}
wait

#-cipher PSK
eval "${GETPORT}"
launch_bare_server "$OPENSSL" s_server -quiet -www -accept "${PORT}" -tls1 -keyform pem -certform pem ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" -cipher 'PSK:@SECLEVEL=1' -psk 9e32cf7786321a828ef7668f09fb35db >/dev/null
PID=$!
wait_server ${PID}

echo "${PREFIX}Checking TLS 1.0 with PSK..."
${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.0:+PSK${ADD}" --pskusername Client_identity --pskkey 9e32cf7786321a828ef7668f09fb35db --insecure </dev/null >/dev/null || \
	fail ${PID} "Failed"

kill ${PID}
wait

if test ${NO_TLS1_2} = 0; then
	# Tests requiring openssl 1.0.1 - TLS 1.2
	#-cipher RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA
	eval "${GETPORT}"
	launch_bare_server "$OPENSSL" s_server -cipher 'ALL:@SECLEVEL=1' -sigalgs "$SIGALGS" -quiet -www -accept "${PORT}" -keyform pem -certform pem -tls1_2 ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" ${DSA_PARAMS} -Verify 1 -CAfile "${CA_CERT}" >/dev/null
	PID=$!
	wait_server ${PID}

	echo "${PREFIX}Checking TLS 1.2 with RSA and AES-128-GCM..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-128-GCM:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.2 with RSA and AES-256-GCM..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-256-GCM:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	echo "${PREFIX}Checking TLS 1.2 with DHE-RSA..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+DHE-RSA${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	if test "${NO_DSS}" = 0; then
		echo "${PREFIX}Checking TLS 1.2 with DHE-DSS..."
		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+DHE-DSS:+SIGN-DSA-SHA1:%VERIFY_ALLOW_SIGN_WITH_SHA1:+SIGN-DSA-SHA256${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
			fail ${PID} "Failed"
	fi

	echo "${PREFIX}Checking TLS 1.2 with ECDHE-RSA..."
	"${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+ECDHE-RSA:+CURVE-ALL${ADD}" --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	if test "${HAVE_X25519}" = 0; then
		eval "${GETPORT}"
		launch_bare_server "$OPENSSL" s_server -quiet -www -accept "${PORT}" -keyform pem -certform pem -tls1_2 -key "${RSA_KEY}" -cert "${RSA_CERT}" -curves X25519 -CAfile "${CA_CERT}" >/dev/null
		PID=$!
		wait_server ${PID}

		echo "${PREFIX}Checking TLS 1.2 with ECDHE-RSA (X25519)..."
		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+ECDHE-RSA:+CURVE-X25519${ADD}" --insecure --x509certfile "${RSA_CERT}" --x509keyfile "${RSA_KEY}" </dev/null >/dev/null || \
			fail ${PID} "Failed"

		kill ${PID}
		wait
	fi

	if test "${FIPS_CURVES}" != 1; then
		#-cipher ECDHE-ECDSA-AES128-SHA
		eval "${GETPORT}"
		launch_bare_server "$OPENSSL" s_server -quiet -www -accept "${PORT}" -keyform pem -certform pem -tls1_2 -key "${ECC224_KEY}" -cert "${ECC224_CERT}" -Verify 1 -named_curve secp224r1 -CAfile "${CA_ECC_CERT}" >/dev/null
		PID=$!
		wait_server ${PID}

		echo "${PREFIX}Checking TLS 1.2 with ECDHE-ECDSA... (SECP224R1)"
		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+ECDHE-ECDSA:+CURVE-SECP224R1:+CURVE-ALL${ADD}" --insecure --x509certfile "${ECC224_CERT}" --x509keyfile "${ECC224_KEY}" </dev/null >/dev/null || \
			fail ${PID} "Failed"

		kill ${PID}
		wait
	fi

	#-cipher ECDHE-ECDSA-AES128-SHA
	eval "${GETPORT}"
	launch_bare_server "$OPENSSL" s_server -quiet -www -accept "${PORT}" -keyform pem -certform pem -tls1_2 -key "${ECC384_KEY}" -cert "${ECC384_CERT}" -Verify 1 -named_curve secp384r1 -CAfile "${CA_ECC_CERT}" >/dev/null
	PID=$!
	wait_server ${PID}

	echo "${PREFIX}Checking TLS 1.2 with ECDHE-ECDSA... (SECP384R1)"
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+ECDHE-ECDSA:+CURVE-ALL${ADD}" --insecure --x509certfile "${ECC384_CERT}" --x509keyfile "${ECC384_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	kill ${PID}
	wait

	if test "${FIPS_CURVES}" != 1; then
		#-cipher ECDHE-ECDSA-AES128-SHA
		eval "${GETPORT}"
		launch_bare_server "$OPENSSL" s_server -quiet -www -accept "${PORT}" -keyform pem -certform pem -tls1_2 -key "${ECC521_KEY}" -cert "${ECC521_CERT}" -Verify 1 -named_curve secp521r1 -CAfile "${CA_ECC_CERT}" >/dev/null
		PID=$!
		wait_server ${PID}

		echo "${PREFIX}Checking TLS 1.2 with ECDHE-ECDSA... (SECP521R1)"
		${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+ECDHE-ECDSA:+CURVE-ALL${ADD}" --insecure --x509certfile "${ECC521_CERT}" --x509keyfile "${ECC521_KEY}" </dev/null >/dev/null || \
			fail ${PID} "Failed"

		kill ${PID}
		wait
	fi #FIPS_CURVES
fi #NO_TLS1_2

#-cipher PSK
eval "${GETPORT}"
launch_bare_server "$OPENSSL" s_server -quiet -www -accept "${PORT}" -tls1_2 -keyform pem -certform pem ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" -cipher PSK -psk 9e32cf7786321a828ef7668f09fb35db >/dev/null
PID=$!
wait_server ${PID}

echo "${PREFIX}Checking TLS 1.2 with PSK..."
${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-TLS1.2:+PSK:+CURVE-ALL${ADD}" --insecure --pskusername Client_identity --pskkey 9e32cf7786321a828ef7668f09fb35db </dev/null >/dev/null || \
	fail ${PID} "Failed"

kill ${PID}
wait

eval "${GETPORT}"
launch_bare_server "$OPENSSL" s_server -cipher 'ALL:@SECLEVEL=1' -quiet -accept "${PORT}" -keyform pem -certform pem -dtls1 -timeout ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" ${DSA_PARAMS} -Verify 1 -CAfile "${CA_CERT}" >/dev/null
PID=$!
wait_udp_server ${PID}

# Test DTLS 1.0 with RSA ciphersuite
echo "${PREFIX}Checking DTLS 1.0 with RSA..."
${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-DTLS1.0:+RSA${ADD}" --udp --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
	fail ${PID} "Failed"

kill ${PID}
wait

eval "${GETPORT}"
launch_bare_server "$OPENSSL" s_server -cipher 'ALL:@SECLEVEL=1' -quiet -accept "${PORT}" -keyform pem -certform pem -dtls1 -timeout ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" ${DSA_PARAMS} -Verify 1 -CAfile "${CA_CERT}" >/dev/null
PID=$!
wait_udp_server ${PID}

# Test DTLS 1.0 with DHE-RSA ciphersuite
echo "${PREFIX}Checking DTLS 1.0 with DHE-RSA..."
${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-DTLS1.0:+DHE-RSA${ADD}" --udp --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
	fail ${PID} "Failed"

kill ${PID}
wait

if test "${NO_DSS}" = 0; then
	eval "${GETPORT}"
	launch_bare_server "$OPENSSL" s_server -cipher "ALL:@SECLEVEL=1" -quiet -accept "${PORT}" -keyform pem -certform pem -dtls1 -timeout ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" ${DSA_PARAMS} -Verify 1 -CAfile "${CA_CERT}" >/dev/null
	PID=$!
	wait_udp_server ${PID}

	# Test DTLS 1.0 with DHE-DSS ciphersuite
	echo "${PREFIX}Checking DTLS 1.0 with DHE-DSS..."
	${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-DTLS1.0:+DHE-DSS:+SIGN-DSA-SHA1:+SIGN-DSA-SHA256${ADD}" --udp --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
		fail ${PID} "Failed"

	kill ${PID}
	wait
fi

eval "${GETPORT}"
launch_bare_server "$OPENSSL" s_server -cipher 'ALL:@SECLEVEL=1' -quiet -accept "${PORT}" -keyform pem -certform pem -dtls1_2 -timeout ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" ${DSA_PARAMS} -Verify 1 -CAfile "${CA_CERT}" >/dev/null
PID=$!
wait_udp_server ${PID}

echo "${PREFIX}Checking DTLS 1.2 with AES-CBC..."
${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+AES-128-CBC:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-DTLS1.2:+RSA${ADD}" --udp --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
	fail ${PID} "Failed"

kill ${PID}
wait

eval "${GETPORT}"
launch_bare_server "$OPENSSL" s_server -cipher ALL -quiet -accept "${PORT}" -keyform pem -certform pem -dtls1_2 -timeout ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" -Verify 1 -CAfile "${CA_CERT}" >/dev/null
PID=$!
wait_udp_server ${PID}

# Test DTLS 1.2 with RSA ciphersuite
echo "${PREFIX}Checking DTLS 1.2 with RSA..."
${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+MAC-ALL:+VERS-DTLS1.2:+RSA${ADD}" --udp --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
	fail ${PID} "Failed"

kill ${PID}
wait

eval "${GETPORT}"
launch_bare_server "$OPENSSL" s_server -cipher ALL -quiet -accept "${PORT}" -keyform pem -certform pem -dtls1_2 -timeout ${OPENSSL_DH_PARAMS_OPT} -key "${RSA_KEY}" -cert "${RSA_CERT}" -Verify 1 -CAfile "${CA_CERT}" >/dev/null
PID=$!
wait_udp_server ${PID}

echo "${PREFIX}Checking DTLS 1.2 with ECDHE-RSA..."
${VALGRIND} "${CLI}" ${DEBUG} -p "${PORT}" 127.0.0.1 --priority "NONE:+CIPHER-ALL:+SIGN-ALL:+COMP-NULL:+GROUP-ALL:+MAC-ALL:+VERS-DTLS1.2:+ECDHE-RSA${ADD}" --udp --insecure --x509certfile "${CLI_CERT}" --x509keyfile "${CLI_KEY}" </dev/null >/dev/null || \
	fail ${PID} "Failed"

kill ${PID}
wait
