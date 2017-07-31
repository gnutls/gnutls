#!/bin/sh

HEADER=$(pkg-config --cflags-only-I p11-kit-1|awk '{print $1}'|sed 's/-I//g')
HEADER="${HEADER}/p11-kit/pkcs11.h"

echo "const char *mech_list[] = {"

# Exclude duplicate and uninteresting entries
EXCLUDED="(CKM_VENDOR_DEFINED\s|CKM_CAST128_MAC\s|CKM_CAST128_KEY_GEN\s|CKM_CAST128_ECB\s|CKM_CAST128_CBC\s|CKM_CAST128_MAC_GENERAL\s|CKM_CAST128_CBC_PAD\s|CKM_PBE_MD5_CAST128_CBC\s|CKM_PBE_SHA1_CAST128_CBC\s|CKM_EC_KEY_PAIR_GEN\s)"

cat ${HEADER}|grep -E "define\sCKM_"|grep -vE "${EXCLUDED}"|awk '{print "\t["$3"] = \""$2"\","}'


echo "};"

