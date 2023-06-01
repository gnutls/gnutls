#!/bin/sh
# ./scan-gnutls.sh > gnutls-ciphers.js

echo 'var gnutls_ciphersuites = {'

: ${srcdir=.}
: ${top_builddir=../..}

gcc -E "${srcdir}/../../lib/algorithms/ciphersuites.c" -I"${top_builddir}" -I"${srcdir}/../../lib" -DHAVE_CONFIG_H -DHAVE_LIBNETTLE -I"${srcdir}/../../gl" -I"${srcdir}/../../lib/includes" -DENABLE_DHE -DENABLE_ECDHE -DENABLE_PSK -DENABLE_ANON -DENABLE_SRP \
	| awk '/^static const gnutls_cipher_suite_entry_st cs_algorithms/, /;/ { print; }' \
	| grep '{' | head -n-1 | tail -n+2 \
	| sed -r -e 's#\{ *0x(..), *0x(..) *\}#0x\1\2#;s# *\{ *"#"#;s#\}##;s#, +# #g' \
		-e 's#GNUTLS_VERSION_UNKNOWN#unknown#' \
		-e 's#GNUTLS_DTLS_VERSION_MIN#GNUTLS_DTLS1_0#;s#GNUTLS_TLS1 #GNUTLS_TLS1_0 #' \
		-e 's#TLS([0-9])_([0-9])#TLS\1.\2#g;s#GNUTLS_SSL3#SSL3.0#;s#_#-#g;s#GNUTLS-(CIPHER|KX|MAC)-##g;s#GNUTLS-##g' \
	| gawk --non-decimal-data '{ if ($6 == "AEAD") { mac = $11; } else { mac = $6; }; sub("UMAC-", "UMAC", mac); sub("DIG-", "", mac); if (mac == "SHA1") { mac = "SHA"; } \
		cipher = $4; sub("ARCFOUR", "RC4", cipher); sub("3DES-CBC", "3DES-EDE-CBC", cipher); \
		gnutlsname = $1; sub(",", "", gnutlsname); \
		kx = $5; if (sub("ANON-", "", kx)) { kx = kx "-anon"; }; sub("SRP", "SRP-SHA", kx); \
		if ($6 != "AEAD" || cipher ~ /GCM/) { name = "TLS_" kx "_WITH_" cipher "_" mac; } else { name = "TLS_" kx "_WITH_" cipher }; \
		gsub("-", "_", name); printf ("%d#  \"%s\": { id: %s, name: \"%s\", gnutlsname: %s, cipher: \"%s\", kx: \"%s\", mac: \"%s\", min_version: \"%s\", min_dtls_version: \"%s\", prf: \"%s\" },\n", $2, name, $2, name, gnutlsname, $4, $5, $6, $7, $9, $11) }' \
	| sort -n \
	| cut -d'#' -f2- \
	| column -t \
	| sed -e 's#:  #: #g;s#,  #, #g;s#{  #{ #g;s#^#  #'
echo '};'
