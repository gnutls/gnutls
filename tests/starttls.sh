#!/bin/sh

# Copyright (C) 2010-2016 Free Software Foundation, Inc.
#
# Author: Nikos Mavrogiannopoulos
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

srcdir="${srcdir:-.}"
SERV="${SERV:-../src/gnutls-serv${EXEEXT}}"
CLI="${CLI:-../src/gnutls-cli${EXEEXT}}"
unset RETCODE

if ! test -x "${SERV}"; then
	exit 77
fi

if ! test -x "${CLI}"; then
	exit 77
fi

if test "${WINDIR}" != ""; then
	exit 77
fi 

if ! test -z "${VALGRIND}"; then
	VALGRIND="${LIBTOOL:-libtool} --mode=execute ${VALGRIND} --error-exitcode=15"
fi

if test ! -x /usr/bin/socat;then
	exit 77
fi

for file in `which chat` /sbin/chat /usr/sbin/chat /usr/local/sbin/chat
do
	if test -x "$file"
	then
		CHAT="$file"
		break
	fi
done

if test -z "$CHAT"
then
	echo "chat not found"
	exit 77
fi

SERV="${SERV} -q"

. "${srcdir}/scripts/common.sh"

echo "Checking STARTTLS"

eval "${GETPORT}"
launch_server $$ --echo --priority "NORMAL:+ANON-ECDH"
PID=$!
wait_server ${PID}

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --priority NORMAL:+ANON-ECDH --insecure --starttls </dev/null >/dev/null || \
	fail ${PID} "starttls connect should have succeeded!"


kill ${PID}
wait

echo "Checking STARTTLS over SMTP"

eval "${GETPORT}"
socat TCP-LISTEN:${PORT} EXEC:"$CHAT -e -S -v -f ${srcdir}/starttls-smtp.txt",pty &
PID=$!
wait_server ${PID}

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --priority NORMAL:+ANON-ECDH --insecure --starttls-proto smtp --verbose </dev/null >/dev/null
if test $? != 1;then
	fail ${PID} "connect should have failed with error code 1"
fi

kill ${PID}
wait

echo "Checking STARTTLS over FTP"

eval "${GETPORT}"
socat TCP-LISTEN:${PORT} EXEC:"$CHAT -e -S -v -f ${srcdir}/starttls-ftp.txt",pty &
PID=$!
wait_server ${PID}

${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --priority NORMAL:+ANON-ECDH --insecure --starttls-proto ftp --verbose </dev/null >/dev/null
if test $? != 1;then
	fail ${PID} "connect should have failed with error code 1"
fi

kill ${PID}
wait

exit 0
