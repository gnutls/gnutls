#!/bin/sh

: ${srcdir=.}
: ${top_builddir=../..}

nodejs --help >/dev/null 2>&1
if test $? = 0; then
	NODEJS=nodejs
else
	node --help >/dev/null 2>&1
	if test $? = 0; then
		NODEJS=node
	fi
fi

if test -z "${NODEJS}"; then
	echo "You need nodejs to run this test"
	exit 77
fi

set -e

mkdir -p "${top_builddir}/tests/suite/ciphersuite"
"${srcdir}/ciphersuite/scan-gnutls.sh" > "${top_builddir}/tests/suite/ciphersuite/gnutls-ciphers.js"
srcdir="${srcdir}/ciphersuite" builddir="${top_builddir}/tests/suite/ciphersuite" ${NODEJS} "${srcdir}/ciphersuite/test-ciphers.js"
