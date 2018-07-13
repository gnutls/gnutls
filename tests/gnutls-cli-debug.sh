#!/usr/bin/env bash

# Copyright (C) 2017-2018 Red Hat, Inc.
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
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#

srcdir="${srcdir:-.}"
SERV="${SERV:-../src/gnutls-serv${EXEEXT}}"
DCLI="${DCLI:-../src/gnutls-cli-debug${EXEEXT}}"
OUTFILE=cli-debug.$$.tmp
unset RETCODE

if ! test -x "${SERV}"; then
	exit 77
fi

if ! test -x "${DCLI}"; then
	exit 77
fi

if test "${WINDIR}" != ""; then
	exit 77
fi 

if ! test -z "${VALGRIND}"; then
	VALGRIND="${LIBTOOL:-libtool} --mode=execute ${VALGRIND} --error-exitcode=15"
fi


SERV="${SERV} -q"

. "${srcdir}/scripts/common.sh"

check_for_datefudge


KEY1=${srcdir}/../doc/credentials/x509/key-rsa.pem
CERT1=${srcdir}/../doc/credentials/x509/cert-rsa.pem
KEY2=${srcdir}/../doc/credentials/x509/key-ecc.pem
CERT2=${srcdir}/../doc/credentials/x509/cert-ecc.pem
KEY3=${srcdir}/../doc/credentials/x509/key-rsa-pss.pem
CERT3=${srcdir}/../doc/credentials/x509/cert-rsa-pss.pem
CAFILE=${srcdir}/../doc/credentials/x509/ca.pem
TMPFILE=outcert.$$.tmp

# TLS1.1 and TLS1.2 test
echo "Checking output of gnutls-cli-debug for TLS1.1 and TLS1.2 server"

eval "${GETPORT}"
launch_server $$ --echo --priority "NORMAL:-VERS-ALL:+VERS-TLS1.2:+VERS-TLS1.1" --x509keyfile ${KEY1} --x509certfile ${CERT1} \
	--x509keyfile ${KEY2} --x509certfile ${CERT2} --x509keyfile ${KEY3} --x509certfile ${CERT3} >/dev/null 2>&1
PID=$!
wait_server ${PID}

timeout 1800 datefudge "2017-08-9" \
"${DCLI}" -p "${PORT}" localhost >$OUTFILE 2>&1 || fail ${PID} "gnutls-cli-debug run should have succeeded!"

kill ${PID}
wait


declare -a arr=("whether we need to disable TLS 1.2... no" "for TLS 1.0 (RFC2246) support... no"
		"for TLS 1.1 (RFC4346) support... yes" "for TLS 1.2 (RFC5246) support... yes"
		"TLS1.2 neg fallback from TLS 1.6 to... TLS1.2" "for safe renegotiation (RFC5746) support... yes"
		"for encrypt-then-MAC (RFC7366) support... yes" "for ext master secret (RFC7627) support... yes"
		"for RFC7919 Diffie-Hellman support... yes" "for curve SECP256r1 (RFC4492)... yes"
		"for AES-GCM cipher (RFC5288) support... yes"
		"for SHA1 MAC support... yes")

if test "${GNUTLS_FORCE_FIPS_MODE}" != 1;then
#these tests are not run in FIPS mode
arr+=("for MD5 MAC support... no")
arr+=("for ARCFOUR 128 cipher (RFC2246) support... no")
arr+=("for CHACHA20-POLY1305 cipher (RFC7905) support... yes")
fi

for txt in "${arr[@]}"
do
	echo " - Checking ${OUTFILE} for \"${txt}\""
	grep "$txt" $OUTFILE >/dev/null
	if test $? != 0;then
		echo "failed"
		exit 1
	fi
done

rm -f ${OUTFILE}

# TLS1.3 and TLS1.2 test
echo ""
echo "Checking output of gnutls-cli-debug for TLS1.3 and TLS1.2 server"

eval "${GETPORT}"
launch_server $$ --echo --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2" --x509keyfile ${KEY1} --x509certfile ${CERT1} \
	--x509keyfile ${KEY2} --x509certfile ${CERT2} --x509keyfile ${KEY3} --x509certfile ${CERT3} >/dev/null 2>&1
PID=$!
wait_server ${PID}

timeout 1800 datefudge "2017-08-9" \
"${DCLI}" -p "${PORT}" localhost >$OUTFILE 2>&1 || fail ${PID} "gnutls-cli-debug run should have succeeded!"

kill ${PID}
wait

declare -a arr=("whether we need to disable TLS 1.2... no" "for TLS 1.0 (RFC2246) support... no"
		"for TLS 1.1 (RFC4346) support... no" "for TLS 1.2 (RFC5246) support... yes"
		"for TLS 1.3 (draft-ietf-tls-tls13-28) support... yes"
		"TLS1.2 neg fallback from TLS 1.6 to... TLS1.2" "for safe renegotiation (RFC5746) support... yes"
		"for encrypt-then-MAC (RFC7366) support... yes" "for ext master secret (RFC7627) support... yes"
		"for RFC7919 Diffie-Hellman support... yes" "for curve SECP256r1 (RFC4492)... yes"
		"for AES-GCM cipher (RFC5288) support... yes"
		"for SHA1 MAC support... yes")

if test "${GNUTLS_FORCE_FIPS_MODE}" != 1;then
#these tests are not run in FIPS mode
arr+=("for MD5 MAC support... no")
arr+=("for ARCFOUR 128 cipher (RFC2246) support... no")
arr+=("for CHACHA20-POLY1305 cipher (RFC7905) support... yes")
fi

for txt in "${arr[@]}"
do
	echo " - Checking ${OUTFILE} for \"${txt}\""
	grep "$txt" $OUTFILE >/dev/null
	if test $? != 0;then
		echo "failed"
		exit 1
	fi
done

rm -f ${OUTFILE}

exit 0
