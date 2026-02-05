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

# shellcheck shell=sh

: ${srcdir=.}
: ${DANETOOL=../../src/danetool${EXEEXT}}
unset RETCODE

if ! test -x "${DANETOOL}"; then
	exit 77
fi

# Unfortunately it is extremely fragile and fails 99% of the time.
# It also depends on the external infrastructure, specific ports being blocked
# and the DNS resolver setup of the host executing the tests.
if test "${WINDIR}" != ""; then
	exit 77
fi

# First test we're not hitting the overly long DNS name issue.
# We observe that happening when (podman) container names exceed 63 chars.
# https://gitlab.com/gitlab-org/gitlab-runner/-/issues/27763#note_3024302939
if "${DANETOOL}" --check example.com --local-dns 2>&1 | \
		grep "Label length overflow" >/dev/null; then
	echo "DNS name too long (container name >63 chars?)"
	exit 77
fi

. "${srcdir}/../scripts/common.sh"

# Fine hosts

echo ""
echo "*** Testing good HTTPS hosts ***"
HOSTS="www.freebsd.org"
HOSTS="${HOSTS} fedoraproject.org"
HOSTS="${HOSTS} torproject.org"
HOSTS="${HOSTS} nohats.ca"
HOSTS="${HOSTS} jhcloos.com"
HOSTS="${HOSTS} www.afnic.fr"
HOSTS="${HOSTS} www.huque.com"
HOSTS="${HOSTS} www.bortzmeyer.org"
HOSTS="${HOSTS} dns.bortzmeyer.org"
# used to work: good.dane.verisignlabs.com
total_hosts=0
ok_hosts=0
for host in ${HOSTS}; do
	total_hosts=$(expr ${total_hosts} + 1)

	nc -w 5 "${host}" 443 >/dev/null <<_EOF
GET / HTTP/1.0

_EOF
	if test $? != 0; then
		echo "${host}: SKIPPED (unreachable)"
		echo
		continue
	fi

	echo "${host}:"
	if "${DANETOOL}" --check "${host}" 2>&1; then
		ok_hosts=$(expr ${ok_hosts} + 1)
		echo "ok"
	else
		echo "retrying with --local-dns"
		if "${DANETOOL}" --check "${host}" --local-dns 2>&1; then
			ok_hosts=$(expr ${ok_hosts} + 1)
			echo "ok (with --local-dns)"
		else
			echo "FAILED (both attempts)"
		fi
	fi
	echo
done
echo
echo "Total hosts: ${total_hosts}"
echo "Passed hosts: ${ok_hosts}"
required=$(expr ${total_hosts} / 2)
if test ${ok_hosts} -lt 1; then
	echo "FAIL: Not a single good HTTPS host passed!"
	exit 1
fi
if test ${ok_hosts} -lt ${required}; then
	echo "FAIL: ${ok_hosts}/${total_hosts} good HTTPS hosts passed (<50%)"
	exit 1
fi
echo "PASS: ${ok_hosts}/${total_hosts} good HTTPS hosts passed (>=50%)"
echo

echo "*** Testing good SMTP hosts (among reachable SMTP hosts only) ***"
# Note that port 25 is often outright blocked, so here we'd be checking
# ok hosts against reachable hosts, not against total hosts.

HOSTS="nlnetlabs.nl"
HOSTS="${HOSTS} nlnet.nl"
HOSTS="${HOSTS} jhcloos.com"
HOSTS="${HOSTS} openssl.org"
HOSTS="${HOSTS} ietf.org"
reachable_hosts=0
ok_hosts=0
for host in ${HOSTS}; do
	nc -w 5 "${host}" 25 >/dev/null <<_EOF
QUIT
_EOF
	if test $? != 0; then
		echo "${host}: SKIPPED (unreachable)"
		echo
		continue
	fi

	reachable_hosts=$(expr ${reachable_hosts} + 1)
	echo "${host}:"
	if "${DANETOOL}" --check "${host}" --port 25 2>&1; then
		ok_hosts=$(expr ${ok_hosts} + 1)
		echo "ok"
	else
		echo "retrying with --local-dns"
		if "${DANETOOL}" --check "${host}" --port 25 --local-dns 2>&1
		then
			ok_hosts=$(expr ${ok_hosts} + 1)
			echo "ok (with --local-dns)"
		else
			echo "FAILED (both attempts)"
		fi
	fi
	echo
done
echo
echo "Reachable hosts: ${reachable_hosts}"
echo "Passed hosts: ${ok_hosts}"
required=$(expr ${reachable_hosts} / 2)
if test ${ok_hosts} -lt ${required}; then
	echo "FAIL: ${ok_hosts}/${reachable_hosts} SMTP hosts passed (<50%)"
	exit 1
fi
echo "PASS: ${ok_hosts}/${reachable_hosts} SMTP hosts passed (>=50%)"
echo

# *** Testing bad HTTPS hosts ***
# Unfortunately no intentionally broken ones remain up in 2026
# used to work: dane-broken.rd.nic.fr
# used to work: bad-hash.dane.verisignlabs.com
# used to work: bad-params.dane.verisignlabs.com
# used to work: bad-sig.dane.verisignlabs.com
# unintentionally broken ones: www.vulcano.cl www.kumari.net

exit 0
