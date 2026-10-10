#!/bin/bash

# Copyright (C) 2016-2017 Red Hat, Inc.
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

: ${srcdir=.}

if test "${GNUTLS_FORCE_FIPS_MODE}" = 1;then
	echo "Cannot run in FIPS140-2 mode"
	exit 77
fi

tls_fuzzer_prepare() {
VERSIONS="-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2"
if test "${ENABLE_TLS1_1}" = "1"; then
	VERSIONS="${VERSIONS}:+VERS-TLS1.1:+VERS-TLS1.0"
fi
if test "${ENABLE_SSL3}" = "1"; then
	VERSIONS="${VERSIONS}:+VERS-SSL3.0"
fi
PRIORITY="NORMAL:%VERIFY_ALLOW_SIGN_WITH_SHA1:+ARCFOUR-128:+3DES-CBC:+DHE-DSS:+SIGN-DSA-SHA256:+SIGN-DSA-SHA1:-CURVE-SECP192R1:${VERSIONS}:+SHA256:+SHA384:+AES-128-CCM:+AES-256-CCM:+AES-128-CCM-8:+AES-256-CCM-8"
${CLI} --list --priority "${PRIORITY}" >/dev/null 2>&1
if test $? != 0;then
	PRIORITY="NORMAL:%VERIFY_ALLOW_SIGN_WITH_SHA1:+ARCFOUR-128:+3DES-CBC:+DHE-DSS:+SIGN-DSA-SHA256:+SIGN-DSA-SHA1:${VERSIONS}:+SHA256:+SHA384:+AES-128-CCM:+AES-256-CCM:+AES-128-CCM-8:+AES-256-CCM-8"
fi

sed -e "s|@SERVER@|$SERV|g" -e "s/@PORT@/$PORT/g" -e "s/@PRIORITY@/$PRIORITY/g" ../gnutls-nocert.json >${TMPFILE}
if test "${ENABLE_TLS1_1}" != "1"; then
	sed -i '/TLS 1\.[01]/{s/"-x"/"-e"/;n;s/"-X"/"-e"/;}' ${TMPFILE}
	sed -i '/"-e", "check.*TLS 1\.0/{ p; s/TLS 1\.0/TLS 1.1/; }' ${TMPFILE}
	sed -i '/"-e", "Protocol (3, 0)/{ p; s/(3, 0)/(3, 1)/; p; s/(3, 1)/(3, 2)/; }' ${TMPFILE}
	sed -i '/test-export-ciphers-rejected.py/,/"-p"/{s/"-p"/"--min-ver", "TLSv1.2", "-p"/}' ${TMPFILE}
	sed -i 's/"--tls-1.3"/"--tls-1.3", "--min-support", "TLSv1.2"/' ${TMPFILE}
	sed -i '/test-extended-master-secret-extension.py/,/"-p"/{s/"-p"/"-e", "sanity TLSv1.1", "-e", "extended master secret in TLSv1.1", "-p"/}' ${TMPFILE}
	sed -i '/test-TLSv1_2-rejected-without-TLSv1_2.py/{n;s/"arguments"/"exp_pass": false, "arguments"/}' ${TMPFILE}
	sed -i '/skipping over these that need SSL3 support/{s/"comment"/"exp_pass": false, "comment"/}' ${TMPFILE}
	sed -i '/test-chacha20.py/,/"-p"/{s/"-p"/"-e", "Chacha20 in TLS1.1", "-p"/}' ${TMPFILE}
	sed -i '/test-aesccm.py/,/"-p"/{s/"-p"/"-e", "AES-CCM in TLS1.1", "-p"/}' ${TMPFILE}
	ECDHE_EXCLUDES='-e", "Protocol (3, 1) with secp256r1 group", '\
'"-e", "Protocol (3, 1) with secp384r1 group", '\
'"-e", "Protocol (3, 1) with secp521r1 group", '\
'"-e", "Protocol (3, 1) with x25519 group", '\
'"-e", "Protocol (3, 1) with x448 group", '\
'"-e", "Protocol (3, 2) with secp256r1 group", '\
'"-e", "Protocol (3, 2) with secp384r1 group", '\
'"-e", "Protocol (3, 2) with secp521r1 group", '\
'"-e", "Protocol (3, 2) with x25519 group", '\
'"-e", "Protocol (3, 2) with x448 group", '
	sed -i "/test-ecdhe-rsa-key-share-random.py/,/\"-p\"/{s/\"-p\"/\"${ECDHE_EXCLUDES}\"-p\"/}" ${TMPFILE}
	sed -i "/test-ecdhe-padded-shared-secret.py/,/\"-p\"/{s/\"-p\"/\"${ECDHE_EXCLUDES}\"-p\"/}" ${TMPFILE}
fi
}

. "${srcdir}/tls-fuzzer/tls-fuzzer-common.sh"
