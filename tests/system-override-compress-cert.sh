#!/bin/sh

# Copyright (C) 2025 Red Hat, Inc.
#
# Author: Zoltan Fridrich
#
# This file is part of GnuTLS.
#
# GnuTLS is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# GnuTLS is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>

: ${CLI=../src/gnutls-cli${EXEEXT}}

TEST=${builddir}/compress-cert-conf
CONF=config.$$.tmp
export GNUTLS_SYSTEM_PRIORITY_FILE=${CONF}
export GNUTLS_SYSTEM_PRIORITY_FAIL_ON_INVALID=1

if test "${WINDIR}" != ""; then
	exit 77
fi

# The use of brotli is hard-coded in the tls13/compress-cert-conf.c
if ! "$CLI" --list | grep '^Compression: .*COMP-BROTLI'; then
	echo "Not built with brotli, skipping" 1>&2
	exit 77
fi

# We need one other algorithm aside brotli, assuming zstd here
if ! "$CLI" --list | grep '^Compression: .*COMP-ZSTD'; then
	echo "Not built with zstd, skipping" 1>&2
	exit 77
fi

cat <<_EOF_ > ${CONF}
[overrides]
cert-compression-alg = brotli
cert-compression-alg = zstd
_EOF_

${TEST}
if [ $? != 0 ]; then
	echo "${TEST} expected to succeed"
	exit 1
fi
echo "certificate successfully compressed"

unset GNUTLS_SYSTEM_PRIORITY_FILE
unset GNUTLS_SYSTEM_PRIORITY_FAIL_ON_INVALID

${TEST}
if [ $? = 0 ]; then
	echo "${TEST} expected to fail"
	exit 1
fi
echo "certificate compression correctly disabled by default"

exit 0
