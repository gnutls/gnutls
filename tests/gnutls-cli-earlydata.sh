#!/bin/sh

# Copyright (C) 2025 Red Hat, Inc.
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>
#

: ${srcdir=.}
: ${SERV=../src/gnutls-serv${EXEEXT}}
: ${CLI=../src/gnutls-cli${EXEEXT}}
unset RETCODE

if ! test -x "$SERV"; then
	exit 77
fi

if ! test -x "$CLI"; then
	exit 77
fi

if test "$WINDIR" != ""; then
	exit 77
fi

if test -n "$VALGRIND"; then
	VALGRIND="${LIBTOOL:-libtool} --mode=execute $VALGRIND --error-exitcode=1"
fi

SERV="$SERV -q"

. "$srcdir/scripts/common.sh"

: ${ac_cv_sizeof_time_t=8}
if test "$ac_cv_sizeof_time_t" -ge 8; then
	ATTIME_VALID="2038-10-12"  # almost the pregenerated cert expiration
else
	ATTIME_VALID="2030-12-17"  # end of epoch − 2590 days of validity
fi

testdir=`create_testdir earlydata`
KEY="$srcdir/../doc/credentials/x509/key-ecc.pem"
CERT="$srcdir/../doc/credentials/x509/cert-ecc.pem"
CACERT="$srcdir/../doc/credentials/x509/ca.pem"

eval "$GETPORT"
launch_server --echo --x509keyfile "$KEY" --x509certfile "$CERT" --disable-client-cert --earlydata --maxearlydata 1000
PID=$!
wait_server "$PID"

echo "This is a test message" > "$testdir/earlydata.txt"

$VALGRIND "$CLI" --attime="$ATTIME_VALID" -p "$PORT" localhost --logfile="$testdir/cli.log" --priority="NORMAL:-VERS-ALL:+VERS-TLS1.3" --x509cafile "$CACERT" --resume --waitresumption --earlydata="$testdir/earlydata.txt" </dev/null >"$testdir/cli.out"
if test $? -ne 0; then
	cat "$testdir/cli.log"
	fail "$PID" "failed to communicate with the server"
fi

if ! grep "This is a resumed session" "$testdir/cli.log" > /dev/null; then
	fail "$PID" "session is not resumed"
fi

if ! cmp "$testdir/earlydata.txt" "$testdir/cli.out" > /dev/null; then
	fail "$PID" "early data has not been sent back"
fi

kill "$PID"
wait

exit 0
