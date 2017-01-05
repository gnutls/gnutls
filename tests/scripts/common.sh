# Copyright (C) 2011-2016 Free Software Foundation, Inc.
# Copyright (C) 2015-2016 Red Hat, Inc.
#
# This file is part of GnuTLS.
#
# The launch_server() function was contributed by Cedric Arbogast.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

export TZ="UTC"

GETPORT='rc=0;myrandom=$(date +%N | sed 's/^0*//');while test $rc = 0;do PORT="$(((($$<<15)|$myrandom) % 63001 + 2000))";
	netstat -anl|grep "[\:\.]$PORT" >/dev/null 2>&1;
	rc=$?;done;'

check_for_datefudge() {
	TSTAMP=`datefudge -s "2006-09-23" date -u +%s || true`
	if test "$TSTAMP" != "1158969600" || test "$WINDOWS" = 1; then
	echo $TSTAMP
		echo "You need datefudge to run this test"
		exit 77
	fi
}

fail() {
   PID="$1"
   shift
   echo "Failure: $1" >&2
   [ -n "${PID}" ] && kill ${PID}
   exit 1
}

wait_for_port()
{
	local ret
	local PORT="$1"
	sleep 4

	for i in 1 2 3 4 5 6;do
		netstat -anl|grep "[\:\.]$PORT"|grep LISTEN >/dev/null 2>&1
		ret=$?
		if test $ret != 0;then
		netstat -anl|grep "[\:\.]$PORT"
			echo try $i
			sleep 2
		else
			break
		fi
	done
	return $ret
}

wait_for_free_port()
{
	local ret
	local PORT="$1"

	for i in 1 2 3 4 5 6;do
		netstat -anl|grep "[\:\.]$PORT" >/dev/null 2>&1
		ret=$?
		if test $ret != 0;then
			break
		else
			sleep 20
		fi
	done
	return $ret
}

launch_server() {
	PARENT="$1"
	shift

	wait_for_free_port ${PORT}
	${SERV} ${DEBUG} -p "${PORT}" $* >/dev/null 2>&1 &
}

launch_pkcs11_server() {
	PARENT="$1"
	shift
	PROVIDER="$1"
	shift

	wait_for_free_port ${PORT}

	${VALGRIND} ${SERV} ${PROVIDER} ${DEBUG} -p "${PORT}" $* &
}

launch_bare_server() {
	PARENT="$1"
	shift

	wait_for_free_port ${PORT}
	${SERV} $* >/dev/null 2>&1 &
}

wait_server() {
	local PID=$1
	trap "test -n \"${PID}\" && kill ${PID};exit 1" 1 15 2
	wait_for_port $PORT
	if test $? != 0;then
		echo "Server $PORT did not come up"
		kill $PID
		exit 1
	fi
}

wait_udp_server() {
	local PID=$1
	trap "test -n \"${PID}\" && kill ${PID};exit 1" 1 15 2
	sleep 4
}

