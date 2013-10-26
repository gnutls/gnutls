#! /bin/sh

nodejs --help >/dev/null || ( echo "You need nodejs to run this test" && exit 77 )

set -e

cd ciphersuite && ( \
./scan-gnutls.sh > gnutls-ciphers.js && \
nodejs test-ciphers.js )
