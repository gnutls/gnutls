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

srcdir="${srcdir:-.}"

tls_fuzzer_prepare() {
PRIORITY="NORMAL:-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2:+VERS-TLS1.1:-KX-ALL:+DHE-PSK:+ECDHE-PSK:+PSK"

PSKKEY=8a7759b3f26983c453e448060bde8981
PSKID=test

sed -e "s|@SERVER@|$SERV|g" -e "s/@PSKKEY@/$PSKKEY/g" -e "s/@PSKID@/$PSKID/g" -e "s/@PSKFILE@/$PSKFILE/g" -e "s/@PORT@/$PORT/g" -e "s/@PRIORITY@/$PRIORITY/g" ../gnutls-psk.json >${TMPFILE}

cat >${PSKFILE} <<_EOF_
${PSKID}:${PSKKEY}
_EOF_
}

. "${srcdir}/tls-fuzzer/tls-fuzzer-common.sh"
