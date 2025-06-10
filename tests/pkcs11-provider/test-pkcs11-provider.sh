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

: ${testdir=$abs_top_builddir/tests/pkcs11-provider}

if test "${GNUTLS_FORCE_FIPS_MODE}" != 1; then
	exit 77
fi

if [ -z "$(which pkcs11-tool 2>/dev/null)" ]; then
	echo "Need pkcs11-tool from opensc package to run this test."
	exit 77
fi

MODULE="/lib64/pkcs11/libkryoptic_pkcs11.so"
if [ ! -f "$MODULE" ]; then
        echo "Need Kryoptic module to run this test."
        exit 77
fi

LABEL="Kryoptic Token"
PIN="12345"
PRIORITY_FILE="${testdir}/gnutls.$$.conf"
KRYOPTIC_DB="${testdir}/kryoptic.$$.sql"
export KRYOPTIC_CONF="${testdir}/kryoptic.$$.conf"
export GNUTLS_SYSTEM_PRIORITY_FAIL_ON_INVALID=1
export GNUTLS_SYSTEM_PRIORITY_FILE="${PRIORITY_FILE}"
export GNUTLS_DEBUG_LEVEL=6

cat >"${PRIORITY_FILE}" <<_EOF_
[overrides]
allow-rsa-pkcs1-encrypt = true

[provider]
path = ${MODULE}
pin = ${PIN}
_EOF_

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
pkcs11-tool --module "${MODULE}" --init-token --label "${LABEL}" --so-pin "${PIN}" >/dev/null
if test $? != 0; then
	echo "failed to initialize token"
	exit 1
fi
# set user pin
pkcs11-tool --module "${MODULE}" --so-pin "${PIN}"  --login --login-type so --init-pin --pin "${PIN}" >/dev/null
if test $? != 0; then
	echo "failed to set user pin"
	exit 1
fi

echo "Testing public key algorithms"
"${testdir}/pkcs11-provider-pk"
rc=$?
if test "${rc}" = "0"; then
	echo "test passed"
else
	echo "test failed"
	rm -f ${PRIORITY_FILE} ${KRYOPTIC_CONF} ${KRYOPTIC_DB}
	exit ${rc}
fi

echo "Testing signatures"
"${testdir}/pkcs11-provider-sig"
rc=$?
if test "${rc}" = "0"; then
	echo "test passed"
else
	echo "test failed"
	rm -f ${PRIORITY_FILE} ${KRYOPTIC_CONF} ${KRYOPTIC_DB}
	exit ${rc}
fi

echo "Testing ciphers"
"${testdir}/pkcs11-provider-cipher"
rc=$?
if test "${rc}" = "0"; then
	echo "test passed"
else
	echo "test failed"
	rm -f ${PRIORITY_FILE} ${KRYOPTIC_CONF} ${KRYOPTIC_DB}
	exit ${rc}
fi

echo "Testing hmacs"
"${testdir}/pkcs11-provider-hmac"
rc=$?
if test "${rc}" = "0"; then
	echo "test passed"
else
	echo "test failed"
	rm -f ${PRIORITY_FILE} ${KRYOPTIC_CONF} ${KRYOPTIC_DB}
	exit ${rc}
fi

rm -f ${PRIORITY_FILE} ${KRYOPTIC_CONF} ${KRYOPTIC_DB}
exit ${rc}
