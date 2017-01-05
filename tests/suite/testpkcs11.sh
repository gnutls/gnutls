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
# along with GnuTLS; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

srcdir="${srcdir:-.}"
P11TOOL="${P11TOOL:-../../src/p11tool${EXEEXT}}"
CERTTOOL="${CERTTOOL:-../../src/certtool${EXEEXT}}"
DIFF="${DIFF:-diff -b -B}"
SERV="${SERV:-../../src/gnutls-serv${EXEEXT}}"
CLI="${CLI:-../../src/gnutls-cli${EXEEXT}}"
RETCODE=0

if ! test -x "${P11TOOL}"; then
	exit 77
fi

if ! test -x "${CERTTOOL}"; then
	exit 77
fi

if ! test -x "${SERV}"; then
	exit 77
fi

if ! test -x "${CLI}"; then
	exit 77
fi

if ! test -z "${VALGRIND}"; then
	VALGRIND="${LIBTOOL:-libtool} --mode=execute valgrind --leak-check=full"
fi

TMPFILE="testpkcs11.debug"
CERTTOOL_PARAM="--stdout-info"

if test "${WINDIR}" != ""; then
	exit 77
fi 

P11TOOL="${VALGRIND} ${P11TOOL} --batch"
SERV="${SERV} -q"

. ${srcdir}/../scripts/common.sh

rm -f "${TMPFILE}"

exit_error () {
	echo "check ${TMPFILE} for additional debugging information"
	echo ""
	echo ""
	tail "${TMPFILE}"
	exit 1
}

# $1: token
# $2: PIN
# $3: filename
# ${srcdir}/pkcs11-certs/client.key
write_privkey () {
	export GNUTLS_PIN="$2"
	filename="$3"
	token="$1"

	echo -n "* Writing a client private key... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --write --label gnutls-client2 --load-privkey "${filename}" "${token}" >>"${TMPFILE}" 2>&1
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit_error
	fi

	echo -n "* Checking whether object was marked private... "
	${P11TOOL} ${ADDITIONAL_PARAM} --list-privkeys "${token};object=gnutls-client2" 2>/dev/null | grep 'Label\:' >>"${TMPFILE}" 2>&1
	if test $? = 0; then
		echo "private object was public"
		exit_error
	fi
	echo ok

}

# $1: token
# $2: PIN
# $3: filename
write_serv_privkey () {
	export GNUTLS_PIN="$2"
	filename="$3"
	token="$1"

	echo -n "* Writing the server private key... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --write --label serv-key --load-privkey "${filename}" "${token}" >>"${TMPFILE}" 2>&1
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit_error
	fi

}

# $1: token
# $2: PIN
# $3: filename
write_serv_pubkey () {
	export GNUTLS_PIN="$2"
	filename="$3"
	token="$1"

	echo -n "* Writing the server public key... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --write --label serv-pubkey --load-pubkey "${filename}" "${token}" >>"${TMPFILE}" 2>&1
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit_error
	fi

	#verify it being written
	${P11TOOL} ${ADDITIONAL_PARAM} --login --list-all "${token};object=serv-pubkey;type=public" >>"${TMPFILE}" 2>&1
	${P11TOOL} ${ADDITIONAL_PARAM} --login --list-all "${token};object=serv-pubkey;type=public"|grep "Public key" >/dev/null 2>&1
	if test $? != 0;then
		echo "Cannot verify the existence of the written pubkey"
		exit_error
	fi
}

# $1: token
# $2: PIN
# $3: filename
write_serv_cert () {
	export GNUTLS_PIN="$2"
	filename="$3"
	token="$1"

	echo -n "* Writing the server certificate... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --write --no-mark-private --label serv-cert --load-certificate "${filename}" "${token}" >>"${TMPFILE}" 2>&1
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit_error
	fi

}

# $1: token
# $2: PIN
# $3: bits
generate_rsa_privkey () {
	export GNUTLS_PIN="$2"
	token="$1"
	bits="$3"

	echo -n "* Generating RSA private key ("${bits}")... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --id 000102030405 --label gnutls-client --generate-rsa --bits "${bits}" "${token}" --outfile tmp-client.pub >>"${TMPFILE}" 2>&1
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit 1
	fi
}

# $1: token
# $2: PIN
# $3: bits
generate_temp_rsa_privkey () {
	export GNUTLS_PIN="$2"
	token="$1"
	bits="$3"

	echo -n "* Generating RSA private key ("${bits}")... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --label temp-rsa-"${bits}" --generate-rsa --bits "${bits}" "${token}" --outfile tmp-client.pub >>"${TMPFILE}" 2>&1
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit 1
	fi

#  if test ${RETCODE} = 0; then
#    echo -n "* Testing private key flags... "
#    ${P11TOOL} ${ADDITIONAL_PARAM} --login --list-keys "${token};object=gnutls-client2;object-type=private" >tmp-client-2.pub 2>>"${TMPFILE}"
#    if test $? != 0; then
#      echo failed
#      exit_error
#    fi
#
#    grep CKA_WRAP tmp-client-2.pub >>"${TMPFILE}" 2>&1
#    if test $? != 0; then
#      echo "failed (no CKA_WRAP)"
#      exit_error
#    else
#      echo ok
#    fi
#  fi
}

generate_temp_dsa_privkey () {
	export GNUTLS_PIN="$2"
	token="$1"
	bits="$3"

	echo -n "* Generating DSA private key ("${bits}")... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --label temp-dsa-"${bits}" --generate-dsa --bits "${bits}" "${token}" --outfile tmp-client.pub >>"${TMPFILE}" 2>&1
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit 1
	fi
}

# $1: token
# $2: PIN
delete_temp_privkey () {
	export GNUTLS_PIN="$2"
	token="$1"
	type="$3"

	test "${RETCODE}" = "0" || return

	echo -n "* Deleting private key... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --delete "${token};object=temp-${type};object-type=private" >>"${TMPFILE}" 2>&1

	if test $? != 0; then
		echo failed
		RETCODE=1
		return
	fi

	RETCODE=0
	echo ok
}

# $1: token
# $2: PIN
# $3: bits
export_pubkey_of_privkey () {
	export GNUTLS_PIN="$2"
	token="$1"
	bits="$3"

	echo -n "* Exporting public key of generated private key... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --export-pubkey "${token};object=gnutls-client;object-type=private" --outfile tmp-client-2.pub >>"${TMPFILE}" 2>&1
	if test $? != 0; then
		echo failed
		exit 1
	fi

	${DIFF} tmp-client.pub tmp-client-2.pub
	if test $? != 0; then
		echo keys differ
		exit 1
	fi

	echo ok
}

# $1: token
# $2: PIN
change_id_of_privkey () {
	export GNUTLS_PIN="$2"
	token="$1"

	echo -n "* Change the CKA_ID of generated private key... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --set-id "01a1b103" "${token};object=gnutls-client;id=%00%01%02%03%04%05;object-type=private" >>"${TMPFILE}" 2>&1
	if test $? != 0; then
		echo failed
		exit_error
	fi

	${P11TOOL} ${ADDITIONAL_PARAM} --login --list-privkeys "${token};object=gnutls-client;object-type=private;id=%01%a1%b1%03" 2>&1 | grep 'ID: 01:a1:b1:03' >>"${TMPFILE}" 2>&1
	if test $? != 0; then
		echo "ID didn't change"
		exit_error
	fi

	echo ok
}

# $1: token
# $2: PIN
change_label_of_privkey () {
	export GNUTLS_PIN="$2"
	token="$1"

	echo -n "* Change the CKA_LABEL of generated private key... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --set-label "new-label" "${token};object=gnutls-client;object-type=private" >>"${TMPFILE}" 2>&1
	if test $? != 0; then
		echo failed
		exit_error
	fi

	${P11TOOL} ${ADDITIONAL_PARAM} --login --list-privkeys "${token};object=new-label;object-type=private" 2>&1 |grep 'Label: new-label' >>"${TMPFILE}" 2>&1
	if test $? != 0; then
		echo "label didn't change"
		exit_error
	fi

	${P11TOOL} ${ADDITIONAL_PARAM} --login --set-label "gnutls-client" "${token};object=new-label;object-type=private" >>"${TMPFILE}" 2>&1
	if test $? != 0; then
		echo failed
		exit_error
	fi

	echo ok
}

# $1: token
# $2: PIN
# $3: bits
generate_temp_ecc_privkey () {
	export GNUTLS_PIN="$2"
	token="$1"
	bits="$3"

	echo -n "* Generating ECC private key (${bits})... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --label "temp-ecc-${bits}" --generate-ecc --bits "${bits}" "${token}" --outfile tmp-client.pub >>"${TMPFILE}" 2>&1
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit 1
	fi
}

# $1: name
# $2: label prefix
# $3: generate option
# $4: token
# $5: PIN
# $6: bits
import_privkey () {
	export GNUTLS_PIN="$5"
	name="$1"
	prefix="$2"
	gen_option="$3"
	token="$4"
	bits="$6"

	outfile="tmp-${prefix}-${bits}.pem"

	echo -n "* Importing ${name} private key (${bits})... "

	"${CERTTOOL}" ${CERTTOOL_PARAM} --generate-privkey "${gen_option}" --pkcs8 --password= --outfile "${outfile}" >>"${TMPFILE}" 2>&1
	if test $? != 0; then
		echo failed
		exit 1
	fi

	${P11TOOL} ${ADDITIONAL_PARAM} --login --write --label "${prefix}-${bits}" --load-privkey "${outfile}" "${token}" >>"${TMPFILE}" 2>&1
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit 1
	fi
}

import_temp_rsa_privkey () {
	import_privkey RSA temp-rsa --rsa $@
}

import_temp_ecc_privkey () {
	import_privkey ECC temp-ecc --ecc $@
}

import_temp_dsa_privkey () {
	import_privkey DSA temp-dsa --dsa $@
}

# $1: token
# $2: PIN
# $3: cakey: ${srcdir}/pkcs11-certs/ca.key
# $4: cacert: ${srcdir}/pkcs11-certs/ca.crt
#
# Tests writing a certificate which corresponds to the given key,
# as well as the CA certificate, and tries to export them.
write_certificate_test () {
	export GNUTLS_PIN="$2"
	token="$1"
	cakey="$3"
	cacert="$4"
	pubkey="$5"

	echo -n "* Generating client certificate... "
	"${CERTTOOL}" ${CERTTOOL_PARAM} ${ADDITIONAL_PARAM}  --generate-certificate --load-ca-privkey "${cakey}"  --load-ca-certificate "${cacert}"  \
	--template ${srcdir}/pkcs11-certs/client-tmpl --load-privkey "${token};object=gnutls-client;object-type=private" \
	--load-pubkey "$pubkey" --outfile tmp-client.crt >>"${TMPFILE}" 2>&1

	if test $? = 0; then
		echo ok
	else
		echo failed
		exit_error
	fi

	echo -n "* Writing client certificate... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --write --id "01a1b103" --label gnutls-client --load-certificate tmp-client.crt "${token}" >>"${TMPFILE}" 2>&1
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit_error
	fi

	echo -n "* Checking whether ID was correctly set... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --list-certs "${token};object=gnutls-client;object-type=private;id=%01%a1%b1%03" 2>&1 | grep 'ID: 01:a1:b1:03' >>"${TMPFILE}" 2>&1
	if test $? != 0; then
		echo "ID was not set on copy"
		exit_error
	fi
	echo ok

	if test -n "${BROKEN_SOFTHSM2}";then
		return
	fi

	echo -n "* Checking whether object was public... "
	${P11TOOL} ${ADDITIONAL_PARAM} --list-all-certs "${token};object=gnutls-client;id=%01%a1%b1%03" 2>&1 | grep 'ID: 01:a1:b1:03' >>"${TMPFILE}" 2>&1
	if test $? != 0; then
		echo "certificate object was not public"
		exit_error
	fi
	echo ok

	if test -n "${BROKEN_SOFTHSM2}";then
		return
	fi

	echo -n "* Writing certificate of client's CA... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --mark-trusted --mark-ca --write --label gnutls-ca --load-certificate "${cacert}" "${token}" >>"${TMPFILE}" 2>&1
	ret=$?
	if test ${ret} != 0; then
		echo "Failed with PIN, trying to write with so PIN" >>"${TMPFILE}"
		${P11TOOL} ${ADDITIONAL_PARAM} --so-login --mark-ca --write --mark-trusted --label gnutls-ca --load-certificate "${cacert}" "${token}" >>"${TMPFILE}" 2>&1
		ret=$?
	fi

	if test ${ret} = 0; then
		echo ok
	else
		echo failed
		exit_error
	fi

	echo -n "* Testing certificate flags... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --list-all-certs "${token};object=gnutls-ca;object-type=cert" |grep Flags|head -n 1 >tmp-client-2.pub 2>>"${TMPFILE}"
	if test $? != 0; then
		echo failed
		exit_error
	fi

	grep CKA_TRUSTED tmp-client-2.pub >>"${TMPFILE}" 2>&1
	if test $? != 0; then
		echo "failed (no CKA_TRUSTED)"
		#exit_error
	fi

	grep "CKA_CERTIFICATE_CATEGORY=CA" tmp-client-2.pub >>"${TMPFILE}" 2>&1
	if test $? != 0; then
		echo "failed (no CKA_CERTIFICATE_CATEGORY=CA)"
		#exit_error
	fi

	echo ok


	echo -n "* Trying to obtain back the cert... "
	${P11TOOL} ${ADDITIONAL_PARAM} --export "${token};object=gnutls-ca;object-type=cert" --outfile crt1.tmp >>"${TMPFILE}" 2>&1
	${DIFF} crt1.tmp "${srcdir}/pkcs11-certs/ca.crt"
	if test $? != 0; then
		echo "failed. Exported certificate differs (crt1.tmp)!"
		exit_error
	fi
	rm -f crt1.tmp
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit_error
	fi

	echo -n "* Trying to obtain the full chain... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --export-chain "${token};object=gnutls-client;object-type=cert"|"${CERTTOOL}" ${CERTTOOL_PARAM}  -i --outfile crt1.tmp >>"${TMPFILE}" 2>&1

	cat tmp-client.crt ${srcdir}/pkcs11-certs/ca.crt|"${CERTTOOL}" ${CERTTOOL_PARAM}  -i >crt2.tmp
	${DIFF} crt1.tmp crt2.tmp
	if test $? != 0; then
		echo "failed. Exported certificate chain differs!"
		exit_error
	fi
	rm -f crt1.tmp crt2.tmp
	if test $? = 0; then
		echo ok
	else
		echo failed
		exit_error
	fi
}

test_sign () {
	export GNUTLS_PIN="$2"
	token="$1"

	echo -n "* Testing signatures using the private key... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --test-sign "${token};object=serv-key" >>"${TMPFILE}" 2>&1
	if test $? != 0; then
		echo "failed. Cannot test signatures."
		exit_error
	fi
	echo ok

	echo -n "* Testing signatures using the private key (with ID)... "
	${P11TOOL} ${ADDITIONAL_PARAM} --login --test-sign "${token};id=%ac%1d%7a%39%cb%72%17%94%66%6c%74%44%73%40%91%44%c0%a0%43%7d" >>"${TMPFILE}" 2>&1
	${P11TOOL} ${ADDITIONAL_PARAM} --login --test-sign "${token};id=%ac%1d%7a%39%cb%72%17%94%66%6c%74%44%73%40%91%44%c0%a0%43%7d" 2>&1|grep "Verifying against public key in the token..."|grep ok >>"${TMPFILE}" 2>&1
	if test $? != 0; then
		echo "failed. Cannot test signatures with ID."
		exit_error
	fi
	echo ok
}

# $1: token
# $2: PIN
# $3: certfile
# $4: keyfile
# $5: cafile
#
# Tests using a certificate and key pair using gnutls-serv and gnutls-cli.
use_certificate_test () {
	export GNUTLS_PIN="$2"
	token="$1"
	certfile="$3"
	keyfile="$4"
	cafile="$5"
	txt="$6"

	echo -n "* Using PKCS #11 with gnutls-cli (${txt})... "
	# start server
	eval "${GETPORT}"
	launch_pkcs11_server $$ "${ADDITIONAL_PARAM}" --echo --priority NORMAL --x509certfile="${certfile}" \
		--x509keyfile="$keyfile" --x509cafile="${cafile}" \
		--require-client-cert >>"${TMPFILE}" 2>&1

	PID=$!
	wait_server ${PID}

	# connect to server using SC
	${VALGRIND} "${CLI}" ${ADDITIONAL_PARAM} -p "${PORT}" localhost --priority NORMAL --x509cafile="${cafile}" </dev/null >>"${TMPFILE}" 2>&1 && \
		fail ${PID} "Connection should have failed!"

	${VALGRIND} "${CLI}" ${ADDITIONAL_PARAM} -p "${PORT}" localhost --priority NORMAL --x509certfile="${certfile}" \
	--x509keyfile="$keyfile" --x509cafile="${cafile}" </dev/null >>"${TMPFILE}" 2>&1 || \
		fail ${PID} "Connection (with files) should have succeeded!"

	${VALGRIND} "${CLI}" ${ADDITIONAL_PARAM} -p "${PORT}" localhost --priority NORMAL --x509certfile="${token};object=gnutls-client;object-type=cert" \
		--x509keyfile="${token};object=gnutls-client;object-type=private" \
		--x509cafile="${cafile}" </dev/null >>"${TMPFILE}" 2>&1 || \
		fail ${PID} "Connection (with SC) should have succeeded!"

	kill ${PID}
	wait

	echo ok
}



echo "Testing PKCS11 support"

# erase SC

type="$1"

if test -z "${type}"; then
	echo "usage: $0: [pkcs15|softhsm|sc-hsm]"
	if test -x "/usr/bin/softhsm" || test -x "/usr/bin/softhsm2-util"; then
		echo "assuming 'softhsm'"
		echo ""
		type=softhsm
	else
		exit 77
	fi

fi

. "${srcdir}/testpkcs11.${type}"

export GNUTLS_PIN=12345678
export GNUTLS_SO_PIN=00000000

init_card "${GNUTLS_PIN}" "${GNUTLS_SO_PIN}"

# find token name
TOKEN=`${P11TOOL} ${ADDITIONAL_PARAM} --list-tokens pkcs11:token=Nikos|grep URL|grep token=GnuTLS-Test|sed 's/\s*URL\: //g'`

echo "* Token: ${TOKEN}"
if test "x${TOKEN}" = x; then
	echo "Could not find generated token"
	exit_error
fi

#write a given privkey
write_privkey "${TOKEN}" "${GNUTLS_PIN}" "${srcdir}/pkcs11-certs/client.key"

generate_temp_ecc_privkey "${TOKEN}" "${GNUTLS_PIN}" 256
delete_temp_privkey "${TOKEN}" "${GNUTLS_PIN}" ecc-256

generate_temp_ecc_privkey "${TOKEN}" "${GNUTLS_PIN}" 384
delete_temp_privkey "${TOKEN}" "${GNUTLS_PIN}" ecc-384

generate_temp_rsa_privkey "${TOKEN}" "${GNUTLS_PIN}" 2048
delete_temp_privkey "${TOKEN}" "${GNUTLS_PIN}" rsa-2048

generate_temp_dsa_privkey "${TOKEN}" "${GNUTLS_PIN}" 3072
delete_temp_privkey "${TOKEN}" "${GNUTLS_PIN}" dsa-3072

import_temp_rsa_privkey "${TOKEN}" "${GNUTLS_PIN}" 1024
delete_temp_privkey "${TOKEN}" "${GNUTLS_PIN}" rsa-1024
import_temp_ecc_privkey "${TOKEN}" "${GNUTLS_PIN}" 256
delete_temp_privkey "${TOKEN}" "${GNUTLS_PIN}" ecc-256
import_temp_dsa_privkey "${TOKEN}" "${GNUTLS_PIN}" 2048
delete_temp_privkey "${TOKEN}" "${GNUTLS_PIN}" dsa-2048

generate_rsa_privkey "${TOKEN}" "${GNUTLS_PIN}" 1024
change_id_of_privkey "${TOKEN}" "${GNUTLS_PIN}"
export_pubkey_of_privkey "${TOKEN}" "${GNUTLS_PIN}"
change_label_of_privkey "${TOKEN}" "${GNUTLS_PIN}"

write_certificate_test "${TOKEN}" "${GNUTLS_PIN}" "${srcdir}/pkcs11-certs/ca.key" "${srcdir}/pkcs11-certs/ca.crt" tmp-client.pub
write_serv_privkey "${TOKEN}" "${GNUTLS_PIN}" "${srcdir}/pkcs11-certs/server.key"
write_serv_cert "${TOKEN}" "${GNUTLS_PIN}" "${srcdir}/pkcs11-certs/server.crt"

write_serv_pubkey "${TOKEN}" "${GNUTLS_PIN}" "${srcdir}/pkcs11-certs/server.crt"
test_sign "${TOKEN}" "${GNUTLS_PIN}"

use_certificate_test "${TOKEN}" "${GNUTLS_PIN}" "${TOKEN};object=serv-cert;object-type=cert" "${TOKEN};object=serv-key;object-type=private" "${srcdir}/pkcs11-certs/ca.crt" "full URLs"

use_certificate_test "${TOKEN}" "${GNUTLS_PIN}" "${TOKEN};object=serv-cert" "${TOKEN};object=serv-key" "${srcdir}/pkcs11-certs/ca.crt" "abbrv URLs"

if test ${RETCODE} = 0; then
	echo "* All smart cards tests succeeded"
fi
rm -f tmp-client.crt tmp-client.pub tmp-client-2.pub "${TMPFILE}"

exit 0
