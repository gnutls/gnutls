#!/bin/bash

# Copyright (C) 2016-2018 Red Hat, Inc.
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

SERV="../../../../src/gnutls-serv${EXEEXT}"
CLI="../../../../src/gnutls-cli${EXEEXT}"

TMPFILE=tls-fuzzer.$$.tmp
PSKFILE=tls-fuzzer.psk.$$.tmp

. "${srcdir}/../scripts/common.sh"

eval "${GETPORT}"

pushd tls-fuzzer

if ! test -d tlsfuzzer;then
	exit 77
fi

pushd tlsfuzzer
test -L ecdsa || ln -s ../python-ecdsa/src/ecdsa ecdsa
test -L tlslite || ln -s ../tlslite-ng/tlslite tlslite 2>/dev/null

wait_for_free_port $PORT

retval=0

tls_fuzzer_prepare

PYTHONPATH=. python tests/scripts_retention.py ${TMPFILE} ${SERV}
retval=$?

rm -f ${TMPFILE}
[ -f "${PSKFILE}" ] && rm -f ${PSKFILE}

popd
popd

exit $retval
