#!/bin/sh

# Copyright (C) 2025 Red Hat, Inc.
#
# Author: Zoltan Fridrich <zfridric@redhat.com>
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
: ${builddir=.}
: ${P11TOOL=../src/p11tool${EXEEXT}}
: ${DIFF=diff}

if test "${GNUTLS_FORCE_FIPS_MODE}" != 1; then
	exit 77
fi

MODULE="/lib64/pkcs11/libkryoptic_pkcs11.so"
if [ ! -f "$MODULE" ]; then
        echo "Need Kryoptic module to run this test."
        exit 77
fi

. ${srcdir}/scripts/common.sh
testdir=`create_testdir pkcs11-provider`

LABEL="Kryoptic Token"
URL="pkcs11:model=v1;manufacturer=Kryoptic%20Project;token=Kryoptic%20Token"
PIN="12345"
KRYOPTIC_DB="${testdir}/kryoptic.sql"
TOKEN_OBJECTS="${testdir}/token-objects.log"
TOKEN_OBJECTS_REFERENCE="${testdir}/token-objects.reference.log"
export KRYOPTIC_CONF="${testdir}/kryoptic.conf"
export GNUTLS_DEBUG_LEVEL=6

cat >"${KRYOPTIC_CONF}" <<_EOF_
[ec_point_encoding]
encoding = "Bytes"

[[slots]]
slot = 22
dbtype = "sqlite"
dbargs = "${KRYOPTIC_DB}"
_EOF_

echo "Initializing token"

# init token
"$P11TOOL" --initialize --label "${LABEL}" --set-so-pin "${PIN}" --provider "${MODULE}" pkcs11: >/dev/null
if test $? != 0; then
	echo "failed to initialize token"
	exit 1
fi

# set user pin
"$P11TOOL" --initialize-pin --set-so-pin "${PIN}" --set-pin "${PIN}" --provider "${MODULE}" pkcs11: >/dev/null
if test $? != 0; then
	echo "failed to set user pin"
	exit 1
fi

PRIORITY_FILE="${testdir}/gnutls.conf"
cat >"${PRIORITY_FILE}" <<_EOF_
[overrides]
allow-rsa-pkcs1-encrypt = true

[provider]
url = ${URL}
pin = ${PIN}
_EOF_

export GNUTLS_SYSTEM_PRIORITY_FAIL_ON_INVALID=1
export GNUTLS_SYSTEM_PRIORITY_FILE="${PRIORITY_FILE}"

list_token() {
	"$P11TOOL" --list-all --provider "${MODULE}" --login \
		--set-pin "${PIN}" "${URL}" >"${TOKEN_OBJECTS}" 2>&1
	rc=$?
	if test "${rc}" != "0"; then
		cat "${TOKEN_OBJECTS}"
		echo 'test failed: listing token objects failed'
		exit "${rc}"
	fi
}

compare_token_to_reference() {
	$DIFF "${TOKEN_OBJECTS_REFERENCE}" "${TOKEN_OBJECTS}"
	rc=$?
	if test "${rc}" != "0"; then
		echo 'test failed: token object list has changed'
		exit "${rc}"
	fi
}

list_token
cat "${TOKEN_OBJECTS}" > "${TOKEN_OBJECTS_REFERENCE}"

echo "Testing public key algorithms"
"${builddir}/pkcs11-provider/pkcs11-provider-pk"
rc=$?
if test "${rc}" = "0"; then
	echo "test passed"
else
	echo "test failed"
	exit ${rc}
fi

echo "Testing signatures"
"${builddir}/pkcs11-provider/pkcs11-provider-sig"
rc=$?
if test "${rc}" = "0"; then
	echo "test passed"
else
	echo "test failed"
	exit ${rc}
fi

echo "Testing ciphers"
"${builddir}/pkcs11-provider/pkcs11-provider-cipher"
rc=$?
if test "${rc}" = "0"; then
	echo "test passed"
else
	echo "test failed"
	exit ${rc}
fi

echo "Testing hmacs"
"${builddir}/pkcs11-provider/pkcs11-provider-hmac"
rc=$?
if test "${rc}" = "0"; then
	echo "test passed"
else
	echo "test failed"
	exit ${rc}
fi

list_token
compare_token_to_reference

rm -rf "$testdir"
