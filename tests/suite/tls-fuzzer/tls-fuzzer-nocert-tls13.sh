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

if test "${GNUTLS_FORCE_FIPS_MODE}" = 1;then
	echo "Cannot run in FIPS140-2 mode"
	exit 77
fi

tls_fuzzer_prepare() {
PRIORITY="NORMAL:-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2"
if test "${ENABLE_TLS1_1}" = "1"; then
	PRIORITY="${PRIORITY}:+VERS-TLS1.1"
fi
PRIORITY="${PRIORITY}:+AES-128-CCM:+AES-256-CCM:+AES-128-CCM-8"

sed -e "s|@SERVER@|$SERV|g" -e "s/@PORT@/$PORT/g" -e "s/@PRIORITY@/$PRIORITY/g" ../gnutls-nocert-tls13.json >${TMPFILE}
if test "${ENABLE_TLS1_1}" != "1"; then
	sed -i '/TLS 1\.[01]\|Protocol (3, [12])/{s/"-x"/"-e"/;n;s/"-X"/"-e"/;}' ${TMPFILE}
	sed -i '/"TLS 1.3 downgrade check for Protocol (3, 1)"/{ p; s/Protocol (3, 1)/Protocol (3, 2)/; }' ${TMPFILE}
	sed -i '/test-tls13-version-negotiation.py/{n;s/"-p"/"-e", "fallback from TLS 1.8 to 1.1", "-p"/}' ${TMPFILE}
fi
}

. "${srcdir}/tls-fuzzer/tls-fuzzer-common.sh"
