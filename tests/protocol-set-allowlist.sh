#!/bin/sh

# Copyright (C) 2021 Red Hat, Inc.
#
# Author: Alexander Sosedkin
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

# The test verifies that gnutls_protocol_set_enabled behaves sensibly.
# The test requires allowlisting and is to be executed
# from within the shell wrapper protocol-set-allowlist.sh
# The shell part of it feeds commands into a C helper
# and compares its output to the reference output.

: ${srcdir=.}
: ${builddir=.}
: ${CERTTOOL=../src/certtool${EXEEXT}}
: ${SERV=../src/gnutls-serv${EXEEXT}}
: ${CLI=../src/gnutls-cli${EXEEXT}}
: ${GREP=grep}
: ${DIFF=diff}
: ${SED=sed}
: ${CAT=cat}
. "${srcdir}/scripts/common.sh"

for tool in "${CERTTOOL}" "${SERV}" "${CLI}"; do
	if ! test -x "$tool"; then
		exit 77
	fi
done

if ! test -z "${VALGRIND}"; then
	VALGRIND="${LIBTOOL:-libtool} --mode=execute ${VALGRIND} --error-exitcode=15"
fi

TMPFILE_TEMPLATE=template.$$.tmpl.tmp
TMPFILE_CERT=cert.$$.pem.tmp
TMPFILE_KEY=key.$$.pem.tmp
TMPFILE_CONFIG=cfg.$$.tmp
TMPFILE_LIST=lst.$$.tmp
TMPFILE_INPUT_SCRIPT=input.$$.script.tmp
TMPFILE_OBSERVED_LOG=observed.$$.log.tmp
TMPFILE_EXPECTED_LOG=expected.$$.log.tmp

# Set up cleanup

SERVER_PID=""
cleanup() {
	test -z "${SERVER_PID}" || kill "${SERVER_PID}"
	rm -f "${TMPFILE_CERT}" "${TMPFILE_KEY}"
	rm -f "${TMPFILE_CONFIG}" "${TMPFILE_LIST}"
	rm -f "${TMPFILE_INPUT_SCRIPT}"
	rm -f "${TMPFILE_OBSERVED_LOG}" "${TMPFILE_EXPECTED_LOG}"
}
trap cleanup 1 15 2 EXIT

# Generate server keys

${CAT} > "$TMPFILE_TEMPLATE" << EOF
organization = test
cn = example.com
ca
tls_www_server
dns_name = example.com
EOF
"${CERTTOOL}" --generate-privkey --key-type=rsa --hash sha256 \
	--outfile "${TMPFILE_KEY}"
"${CERTTOOL}" --generate-self-signed --load-privkey "${TMPFILE_KEY}" \
	--template "${TMPFILE_TEMPLATE}" --outfile "${TMPFILE_CERT}"

# Set up a configuration file using allowlisting allowing for TLS 1.2 only,
# but also allowing to enable 1.1 and 1.3.

${CAT} <<_EOF_ > "${TMPFILE_CONFIG}"
# this following is listed to allow
# 1.3's TLS_AES_128_GCM_SHA256, but not allowlist 1.3 itself
# 1.2's TLS_RSA_AES_128_GCM_SHA256
# 1.1's TLS_RSA_AES_128_CBC_SHA1, but not allowlist 1.1 itself

[global]
override-mode = allowlist

[overrides]
secure-hash = SHA256
tls-enabled-mac = AEAD  # for 1.2, 1.3
tls-enabled-mac = SHA1  # for 1.1
tls-enabled-group = GROUP-FFDHE3072
secure-sig = RSA-PSS-RSAE-SHA256  # for 1.3
secure-sig = RSA-SHA256           # for 1.2, 1.1
tls-enabled-cipher = AES-128-GCM  # for 1.2, 1.3
tls-enabled-cipher = AES-128-CBC  # for 1.1
tls-enabled-kx = RSA
# enabled-version = TLS1.3  # intentional, to be tested for reenablement
enabled-version = TLS1.2    # to be tested for disabling later
# enabled-version = TLS1.1  # intentional, to be tested for reenablement
_EOF_
with_config_file() {
	GNUTLS_SYSTEM_PRIORITY_FILE="${TMPFILE_CONFIG}" \
	GNUTLS_SYSTEM_PRIORITY_FAIL_ON_INVALID=1 \
	"$@"  # preserve $?, callers rely on it
}

# Smoke --list, @SYSTEM

with_config_file "${CLI}" --list -d 4 --priority @SYSTEM > "${TMPFILE_LIST}" 2>&1
if test $? != 0; then
	${CAT} "${TMPFILE_LIST}"
	echo 'fails with just @SYSTEM'
	exit 1
fi
if ! ${GREP} -Fqx 'Protocols: VERS-TLS1.2' "${TMPFILE_LIST}"; then
	${CAT} "${TMPFILE_LIST}"
	echo 'unexpected protocol list with @SYSTEM, must be just VERS-TLS1.2'
	exit 1
fi

# Smoke-test that TLS 1.3 is enableable with these algorithms

with_config_file \
	"${CLI}" --list -d 4 --priority @SYSTEM:+VERS-TLS1.3 > "${TMPFILE_LIST}" 2>&1
if test $? != 0; then
	${CAT} "${TMPFILE_LIST}"
	echo 'listing algorithms fails with @SYSTEM:+VERS-TLS1.3'
	exit 1
fi
if ! ${GREP} -Fqx 'Protocols: VERS-TLS1.2, VERS-TLS1.3' "${TMPFILE_LIST}"; then
	${CAT} "${TMPFILE_LIST}"
	echo 'could not enable TLS 1.3 with a @SYSTEM:+VERS-TLS1.3'
	exit 1
fi

# Smoke-test that TLS 1.1 is enableable with these algorithms

with_config_file \
	"${CLI}" --list -d 4 --priority @SYSTEM:+VERS-TLS1.1 > "${TMPFILE_LIST}" 2>&1
if test $? != 0; then
	${CAT} "${TMPFILE_LIST}"
	echo 'listing algorithms fails with @SYSTEM:+VERS-TLS1.1'
	exit 1
fi
if ! ${GREP} -Fqx 'Protocols: VERS-TLS1.2, VERS-TLS1.1' "${TMPFILE_LIST}"; then
	${CAT} "${TMPFILE_LIST}"
	echo 'could not enable TLS 1.1 with a @SYSTEM:+VERS-TLS1.1'
	exit 1
fi

### Harness for the actual tests

test_with_helper() {
	${CAT} > "$TMPFILE_EXPECTED_LOG"
	${SED} 's/\(.*\) -> .*/> \1/' "${TMPFILE_EXPECTED_LOG}" \
		> "${TMPFILE_INPUT_SCRIPT}"
	with_config_file env \
		TEST_SERVER_PORT=$PORT \
		TEST_SERVER_CA="$TMPFILE_CERT" \
		GNUTLS_DEBUG_LEVEL=9 \
		"${builddir}/protocol-set-allowlist" \
			< "${TMPFILE_INPUT_SCRIPT}" > "${TMPFILE_OBSERVED_LOG}"
	RETCODE=$?
	${DIFF} -u "${TMPFILE_EXPECTED_LOG}" "${TMPFILE_OBSERVED_LOG}"
	DIFF_RETCODE=$?
	if [ $DIFF_RETCODE != 0 ]; then
		echo
		echo 'protocol-set-allowlist(.c) output is unexpected'
		echo '--- expected ---'
		${CAT} "${TMPFILE_EXPECTED_LOG}"
		echo '--- observed ---'
		${CAT} "${TMPFILE_OBSERVED_LOG}"
		exit 1
	fi
	if [ $RETCODE != 0 ]; then
		echo "protocol-set-allowlist(.c) failed with $RETCODE"
		exit 1
	fi
}

### Tests against a TLS 1.2 -only server

eval "${GETPORT}"
# server is launched without allowlisting config file in effect
launch_server --echo --priority "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2" \
	--x509keyfile "${TMPFILE_KEY}" --x509certfile "${TMPFILE_CERT}"
SERVER_PID=$!
wait_server ${SERVER_PID}

# ["gnutls_protocol_set_enabled can disable, TLS"]
# With a configuration file allowlisting a specific TLS protocol version (1.2),
# gnutls_protocol_set_enabled can disable it.
test_with_helper <<EOF
connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
protocol_set_disabled TLS1.2 -> OK
connect -> bad priority: No or insufficient priorities were set.
EOF

# ["gnutls_protocol_set_enabled disables revertibly, TLS"]
# consecutive gnutls_protocol_set_enabled can make connection possible
# (with a different session handle).
test_with_helper <<EOF
connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
protocol_set_disabled TLS1.2 -> OK
connect -> bad priority: No or insufficient priorities were set.
protocol_set_enabled TLS1.2 -> OK
connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
EOF

# Just a random long-ish scenario
test_with_helper <<EOF
connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
protocol_set_disabled TLS1.2 -> OK
connect -> bad priority: No or insufficient priorities were set.
protocol_set_enabled TLS1.3 -> OK
connect -> bad priority: No or insufficient priorities were set.
protocol_set_disabled TLS1.3 -> OK
protocol_set_enabled TLS1.2 -> OK
connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
EOF

# !!! CURRENTLY NOT WORKING AS EXPECTED !!!
# Insufficient priority vs handshake failed
#test_with_helper <<EOF
#protocol_set_disabled TLS1.2 -> OK
#connect -> bad priority: No or insufficient priorities were set.
#protocol_set_enabled TLS1.3 -> OK
#connect -> handshake failed: A packet with illegal or unsupported version was received.
#EOF

terminate_proc ${SERVER_PID}

### Tests against a NORMAL server (all three TLS versions enabled)

eval "${GETPORT}"
# server is launched without allowlisting config file in effect
launch_server -d9 --echo --priority NORMAL \
	--x509keyfile "${TMPFILE_KEY}" --x509certfile "${TMPFILE_CERT}"
SERVER_PID=$!
wait_server ${SERVER_PID}

# !!! CURRENTLY NOT WORKING AS EXPECTED !!!
# smoke-test enabling with protocol_set
#test_with_helper <<EOF
#connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
#protocol_set_enabled TLS1.3 -> OK
#connect -> connection established: (TLS1.3)-(DHE-FFDHE3072)-(RSA-PSS-RSAE-SHA256)-(AES-128-GCM)
#EOF

# !!! CURRENTLY NOT WORKING AS EXPECTED !!!
# ["gnutls_protocol_set_enabled enables, TLS"]
# with a configuration file not allowlisting a specific TLS protocol version,
# enabling that version with gnutls_protocol_set_enabled
# allows connecting to a server accepting this TLS protocol version alone
#test_with_helper <<EOF
#connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
#protocol_set_enabled TLS1.3 -> OK
#connect -> connection established: (TLS1.3)-(DHE-FFDHE3072)-(RSA-PSS-RSAE-SHA256)-(AES-128-GCM)
#EOF

# !!! CURRENTLY NOT WORKING AS EXPECTED !!!
# ["gnutls_protocol_set_enabled enables revertibly, TLS"]
# consecutive gnutls_protocol_set
# can prevent the client from connecting (with a different session handle)
#test_with_helper <<EOF
#connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
#protocol_set_enabled TLS1.1 -> OK
#connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
#protocol_set_disabled TLS1.2 -> OK
#connect -> connection established: (TLS1.1)-(RSA)-(AES-128-CBC)-(SHA1)
#protocol_set_disabled TLS1.1 -> OK
#connect -> bad priority: No or insufficient priorities were set.
#EOF
# Alternative one
#test_with_helper <<EOF
#connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
#protocol_set_enabled TLS1.3 -> OK
#connect -> connection established: (TLS1.3)-(DHE-FFDHE3072)-(RSA-PSS-RSAE-SHA256)-(AES-128-GCM)
#protocol_set_disabled TLS1.3 -> OK
#connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
#EOF

# !!! CURRENTLY NOT WORKING AS EXPECTED !!!
# ["gnutls_protocol_set_disabled disables selectively, TLS"]
# gnutls_protocol_set_disabled with a specific version
# doesn't disable other previously enabled version.
# ["gnutls_protocol_set_enabled enables selectively, TLS"]
# gnutls_protocol_set_enabled enabling a specific version
# doesn't enable other previously disabled version.
#test_with_helper <<EOF
#connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
#protocol_set_enabled TLS1.3 -> OK
#protocol_set_enabled TLS1.2 -> OK
#protocol_set_enabled TLS1.1 -> OK
#connect -> connection established: (TLS1.3)-(DHE-FFDHE3072)-(RSA-PSS-RSAE-SHA256)-(AES-128-GCM)
#protocol_set_disabled TLS1.3 -> OK
#connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
#protocol_set_disabled TLS1.2 -> OK
#connect -> connection established: (TLS1.1)-(RSA)-(AES-128-CBC)-(SHA1)
#protocol_set_disabled TLS1.1 -> OK
#connect -> bad priority: No or insufficient priorities were set.
#protocol_set_enabled TLS1.1 -> OK
#connect -> connection established: (TLS1.1)-(RSA)-(AES-128-CBC)-(SHA1)
#protocol_set_enabled TLS1.2 -> OK
#connect -> connection established: (TLS1.1)-(RSA)-(AES-128-CBC)-(SHA1)
#protocol_set_enabled TLS1.3 -> OK
#connect -> connection established: (TLS1.3)-(DHE-FFDHE3072)-(RSA-PSS-RSAE-SHA256)-(AES-128-GCM)
#EOF

terminate_proc ${SERVER_PID}

### Tests against a TLS 1.1 & 1.3 server (1.2 disabled)

eval "${GETPORT}"
# server is launched without allowlisting config file in effect
launch_server -d9 --echo \
	--priority "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.1:+VERS-TLS1.3" \
	--x509keyfile "${TMPFILE_KEY}" --x509certfile "${TMPFILE_CERT}"
SERVER_PID=$!
wait_server ${SERVER_PID}

# !!! CURRENTLY NOT WORKING AS EXPECTED !!!
#test_with_helper <<EOF
#connect -> handshake failed: A packet with illegal or unsupported version was received.
#protocol_set_enabled TLS1.1 -> OK
#connect -> connection established: (TLS1.1)-(RSA)-(AES-128-CBC)-(SHA1)
#protocol_set_enabled TLS1.3 -> OK
#connect -> connection established: (TLS1.3)-(DHE-FFDHE3072)-(RSA-PSS-RSAE-SHA256)-(AES-128-GCM)
#protocol_set_disabled TLS1.3 -> OK
#connect -> connection established: (TLS1.1)-(RSA)-(AES-128-CBC)-(SHA1)
#protocol_set_disabled TLS1.1 -> OK
#connect -> handshake failed: A packet with illegal or unsupported version was received.
#protocol_set_disabled TLS1.2 -> OK
#connect -> bad priority: No or insufficient priorities were set.
#EOF

terminate_proc ${SERVER_PID}

exit 0
