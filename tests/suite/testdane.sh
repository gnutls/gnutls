#!/bin/sh

# Copyright (C) 2013 Nikos Mavrogiannopoulos
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
: ${DANETOOL=../../src/danetool${EXEEXT}}
unset RETCODE

if ! test -x "${DANETOOL}"; then
	exit 77
fi

# Unfortunately it is extremely fragile and fails 99% of the
# time.
if test "${WINDIR}" != ""; then
	exit 77
fi

. "${srcdir}/../scripts/common.sh"

# Fine hosts

echo ""
echo "*** Testing good HTTPS hosts ***"
# www.vulcano.cl dane.nox.su www.kumari.net
# used to work: good.dane.verisignlabs.com
# used to work: fedoraproject.org
HOSTS="www.freebsd.org torproject.org"
#HOSTS="${HOSTS} nohats.ca"
for host in ${HOSTS}; do

	nc -w 5 "${host}" 443 >/dev/null <<_EOF
GET / HTTP/1.0

_EOF

	if test $? = 0;then
		echo -n "${host}: "
		"${DANETOOL}" --check "${host}" >/dev/null 2>&1
		if [ $? != 0 ]; then
			echo "Error checking ${host}"
			exit 1
		fi
		echo "ok"
	fi
done

echo ""
echo "*** Testing good SMTP hosts ***"
#HOSTS="dougbarton.us nlnetlabs.nl"
HOSTS="nlnetlabs.nl"
for host in ${HOSTS}; do

	nc -w 5 "${host}" 25 >/dev/null <<_EOF
QUIT
_EOF
	
	if test $? = 0;then
		echo -n "${host}: "
		"${DANETOOL}" --check "${host}" --port 25 >/dev/null 2>&1
		if [ $? != 0 ]; then
			echo "Error checking ${host}"
			exit 1
		fi
		echo "ok"
	fi
done

echo ""
echo "*** Testing bad HTTPS hosts ***"
# Not ok
# used to work: dane-broken.rd.nic.fr
# used to work: bad-hash.dane.verisignlabs.com
# used to work: bad-params.dane.verisignlabs.com
# used to work: bad-sig.dane.verisignlabs.com
HOSTS=""
for host in ${HOSTS}; do

	nc -w 5 "${host}" 443 >/dev/null <<_EOF
GET / HTTP/1.0

_EOF
	if test $? = 0;then
		echo -n "${host}: "
		"${DANETOOL}" --check "${host}" >/dev/null 2>&1
		if [ $? = 0 ]; then
			echo "Checking ${host} should have failed"
			exit 1
		fi
		echo "ok"
	fi
done


exit 0
