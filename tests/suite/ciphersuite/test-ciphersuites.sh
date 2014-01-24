#! /bin/sh

nodejs --help >/dev/null 2>&1
if test $? = 0;then
NODEJS=nodejs
else
  node --help >/dev/null 2>&1
  if test $? = 0;then
  NODEJS=node
  fi
fi

if test "z$NODEJS" = "z";then
	echo "You need nodejs to run this test"
	exit 77
fi

set -e

cd ciphersuite && ( \
./scan-gnutls.sh > gnutls-ciphers.js && \
$NODEJS test-ciphers.js )
