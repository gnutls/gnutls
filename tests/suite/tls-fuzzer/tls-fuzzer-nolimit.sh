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

tls_fuzzer_prepare() {
VERSIONS="-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2"
if test "${ENABLE_TLS1_1}" = "1"; then
	VERSIONS="${VERSIONS}:+VERS-TLS1.1:+VERS-TLS1.0"
fi
if test "${ENABLE_SSL3}" = "1"; then
	VERSIONS="${VERSIONS}:+VERS-SSL3.0"
fi
PRIORITY="NORMAL:%VERIFY_ALLOW_SIGN_WITH_SHA1:+ARCFOUR-128:+3DES-CBC:+DHE-DSS:+SIGN-DSA-SHA256:+SIGN-DSA-SHA1:-CURVE-SECP192R1:${VERSIONS}:+SHA256:%ALLOW_SMALL_RECORDS"
${CLI} --list --priority "${PRIORITY}" >/dev/null 2>&1
if test $? != 0;then
	PRIORITY="NORMAL:%VERIFY_ALLOW_SIGN_WITH_SHA1:+ARCFOUR-128:+3DES-CBC:+DHE-DSS:+SIGN-DSA-SHA256:+SIGN-DSA-SHA1:${VERSIONS}:+SHA256:%ALLOW_SMALL_RECORDS"
fi

sed -e "s|@SERVER@|$SERV|g" -e "s/@PORT@/$PORT/g" -e "s/@PRIORITY@/$PRIORITY/g" ../gnutls-nolimit.json >${TMPFILE}
if test "${ENABLE_TLS1_1}" != "1"; then
	sed -i '/TLS 1\.[01]/{s/"-x"/"-e"/;n;s/"-X"/"-e"/;}' ${TMPFILE}
	sed -i '/"-e", "check.*TLS 1\.0/{ p; s/TLS 1\.0/TLS 1.1/; }' ${TMPFILE}
fi
}

. "${srcdir}/tls-fuzzer/tls-fuzzer-common.sh"
