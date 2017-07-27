#!/bin/sh

CERTTOOL="${CERTTOOL:-../../../src/certtool${EXEEXT}}"
OUTPUT=out
TEMPLATE=tmpl

NUM="$1"

if test "${NUM}" = ""; then
	echo "usage: $0 number"
	exit 1
fi

LAST=`expr ${NUM} - 1`

rm -rf "${OUTPUT}"
mkdir -p "${OUTPUT}"

counter=0
while test ${counter} -lt ${NUM}; do
	if test ${counter} = ${LAST}; then
		name="server-${counter}"
	else
		name="CA-${counter}"
	fi

	if test ${counter} = 0; then
	"${CERTTOOL}" --key-type rsa-pss --bits 2048 --hash sha256 --salt-size 64 --generate-privkey >"${OUTPUT}/${name}.key" 2>/dev/null
	# ROOT CA
		echo "cn = ${name}" >"${TEMPLATE}"
		echo "ca" >>"${TEMPLATE}"
		echo "expiration_days = -1" >>"${TEMPLATE}"
		echo "cert_signing_key" >>"${TEMPLATE}"
		echo "crl_signing_key" >>"${TEMPLATE}"
		"${CERTTOOL}" --generate-self-signed --load-privkey "${OUTPUT}/${name}.key" --outfile \
			"${OUTPUT}/${name}.crt" --template "${TEMPLATE}" 2>/dev/null

		echo "expiration_days = -1" >>"${TEMPLATE}"
		"${CERTTOOL}" --generate-crl --load-ca-privkey "${OUTPUT}/${name}.key" --load-ca-certificate "${OUTPUT}/${name}.crt" --outfile \
			"${OUTPUT}/${name}.crl" --template "${TEMPLATE}" 2>/dev/null
	else
		if test ${counter} = ${LAST}; then
	"${CERTTOOL}" --key-type rsa --bits 2048 --generate-privkey >"${OUTPUT}/${name}.key" 2>/dev/null
		# END certificate
			echo "cn = ${name}" >"${TEMPLATE}"
			echo "dns_name = localhost" >>"${TEMPLATE}"
			echo "expiration_days = -1" >>"${TEMPLATE}"
			echo "signing_key" >>"${TEMPLATE}"
			echo "encryption_key" >>"${TEMPLATE}"
			"${CERTTOOL}" --generate-certificate --load-privkey "${OUTPUT}/${name}.key" \
				--load-ca-certificate "${OUTPUT}/${prev_name}.crt" \
				--load-ca-privkey "${OUTPUT}/${prev_name}.key" \
				--outfile "${OUTPUT}/${name}.crt" --template "${TEMPLATE}" -d 4 #2>/dev/null
		else
	"${CERTTOOL}" --key-type rsa-pss --bits 2048 --hash sha384 --salt-size 48 --generate-privkey >"${OUTPUT}/${name}.key" -d 4 #2>/dev/null
		# intermediate CA
			echo "cn = ${name}" >"${TEMPLATE}"
			echo "ca" >>"${TEMPLATE}"
			echo "expiration_days = -1" >>"${TEMPLATE}"
			echo "cert_signing_key" >>"${TEMPLATE}"
			echo "signing_key" >>"${TEMPLATE}"
			"${CERTTOOL}" --generate-certificate --load-privkey "${OUTPUT}/${name}.key" \
				--load-ca-certificate "${OUTPUT}/${prev_name}.crt" \
				--load-ca-privkey "${OUTPUT}/${prev_name}.key" \
				--outfile "${OUTPUT}/${name}.crt" --template "${TEMPLATE}" -d 4 #2>/dev/null
		fi
	fi


	counter=`expr ${counter} + 1`
	prev_name=${name}
done

counter=`expr ${NUM} - 1`
while test ${counter} -ge 0; do
	if test ${counter} = ${LAST}; then
		name="server-${counter}"
	else
		name="CA-${counter}"
	fi

	cat "${OUTPUT}/${name}.crt" >> "${OUTPUT}/chain"

	counter=`expr ${counter} - 1`
done
