#!/bin/sh

# Copyright (C) 2022 Red Hat, Inc.
#
# Author: Daiki Ueno
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GnuTLS. If not, see <https://www.gnu.org/licenses/>.

: ${srcdir=.}
: ${SERV=../src/gnutls-serv${EXEEXT}}
: ${CLI=../src/gnutls-cli${EXEEXT}}

if ! test -x "${SERV}"; then
	exit 77
fi

if ! test -x "${CLI}"; then
	exit 77
fi

. "${srcdir}/scripts/common.sh"

# First check any mismatch in the gnutls-cli --list
if ! "${CLI}" --list | grep '^Groups: .*GROUP-X25519-KYBER768.*' >/dev/null; then
    if "${CLI}" --list | grep '^Public Key Systems: .*KYBER768.*' >/dev/null; then
	fail '' 'KYBER768 is in Public Key Systems, while GROUP-X25519-KYBER768 is NOT in Groups'
    fi
else
    if ! "${CLI}" --list | grep '^Public Key Systems: .*KYBER768.*' >/dev/null; then
	fail '' 'KYBER768 is NOT in Public Key Systems, while GROUP-X25519-KYBER768 is in Groups'
    fi
fi

if ! "${CLI}" --list | grep '^Groups: .*GROUP-\(SECP256R1\|X25519\)-MLKEM768.*' >/dev/null; then
    if "${CLI}" --list | grep '^Public Key Systems: .*ML-KEM-768.*' >/dev/null; then
	fail '' 'ML-KEM-768 is in Public Key Systems, while GROUP-SECP256R1-MLKEM768 or GROUP-X25519-MLKEM768 is NOT in Groups'
    fi
else
    if ! "${CLI}" --list | grep '^Public Key Systems: .*ML-KEM-768.*' >/dev/null; then
	fail '' 'ML-KEM-768 is NOT in Public Key Systems, while GROUP-SECP256R1-MLKEM768 or GROUP-X25519-MLKEM768 is in Groups'
    fi
fi

# If none of those hybrid groups is supported, skip the test
if ! "${CLI}" --list | grep '^Groups: .*GROUP-\(X25519-KYBER768\|SECP256R1-MLKEM768\|X25519-MLKEM768\).*' >/dev/null; then
    exit 77
fi

testdir=`create_testdir pqc-hybrid-kx`

KEY="$srcdir/../doc/credentials/x509/key-ecc.pem"
CERT="$srcdir/../doc/credentials/x509/cert-ecc.pem"
CACERT="$srcdir/../doc/credentials/x509/ca.pem"

# Test all supported hybrid groups
for group in X25519-KYBER768 SECP256R1-MLKEM768 X25519-MLKEM768; do
    if ! "${CLI}" --list | grep "^Groups: .*GROUP-$group.*" >/dev/null; then
	echo "$group is not supported, skipping" >&2
	continue
    fi

    eval "${GETPORT}"
    launch_server --echo --priority "NORMAL:-GROUP-ALL:+GROUP-$group" --x509keyfile="$KEY" --x509certfile="$CERT"
    PID=$!
    wait_server ${PID}

    ${VALGRIND} "${CLI}" -p "${PORT}" localhost --priority "NORMAL:-GROUP-ALL:+GROUP-$group" --x509cafile="$CACERT" --logfile="$testdir/cli.log" </dev/null
    kill ${PID}
    wait

    grep -- "- Description: (TLS1.3-X.509)-(HYBRID-$group)-(ECDSA-SECP256R1-SHA256)-(AES-256-GCM)" "$testdir/cli.log" || { echo "unexpected handshake description"; cat "$testdir/cli.log"; exit 1; }
done

# KEM based groups cannot be used standalone
for group in KYBER768 MLKEM768; do
    if ! "${CLI}" --list | grep "^Groups: .*GROUP-$group.*" >/dev/null; then
	"$group is not supported, skipping"
	continue
    fi

    eval "${GETPORT}"
    launch_server --echo --priority "NORMAL:-GROUP-ALL:+GROUP-$group" --x509keyfile="$KEY" --x509certfile="$CERT"
    PID=$!
    wait_server ${PID}

    ${VALGRIND} "${CLI}" -p "${PORT}" localhost --priority "NORMAL:-GROUP-ALL:+GROUP-$group" --x509cafile="$CACERT" --logfile="$testdir/cli.log" </dev/null
    rc=$?
    kill ${PID}
    wait

    if test $rc -eq 0; then
	fail '' 'Handshake succeeded with a standalone KEM group'
    fi
done

# Check if disabling a curve will also disables hybrid groups with it
cat <<_EOF_ > "$testdir/test.config"
[overrides]

disabled-curve = x25519
_EOF_

for group in X25519-KYBER768 SECP256R1-MLKEM768 X25519-MLKEM768; do
    if ! "${CLI}" --list | grep "^Groups: .*GROUP-$group.*" >/dev/null; then
	echo "$group is not supported, skipping" >&2
	continue
    fi

    eval "${GETPORT}"
    GNUTLS_SYSTEM_PRIORITY_FILE="$testdir/test.config" launch_server --echo --priority "NORMAL:-GROUP-ALL:+GROUP-$group" --x509keyfile="$KEY" --x509certfile="$CERT"
    PID=$!
    wait_server ${PID}

    ${VALGRIND} "${CLI}" -p "${PORT}" localhost --priority "NORMAL:-GROUP-ALL:+GROUP-$group" --x509cafile="$CACERT" --logfile="$testdir/cli.log" </dev/null
    rc=$?
    kill ${PID}
    wait

    case "$group" in
	X25519*)
	    if test $rc -eq 0; then
		fail '' 'Handshake succeeded with a hybrid group with X25519'
	    fi
	    ;;
	*)
	    grep -- "- Description: (TLS1.3-X.509)-(HYBRID-$group)-(ECDSA-SECP256R1-SHA256)-(AES-256-GCM)" "$testdir/cli.log" || { echo "unexpected handshake description"; cat "$testdir/cli.log"; exit 1; }
	    ;;
    esac
done

rm -rf "$testdir"
exit 0
