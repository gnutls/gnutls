#!/bin/bash -eu
#
# (C)2017 Tim Ruehsen tim.ruehsen@gmx.de
#
# View the coverage report for one or more fuzzers.

# 1. execute 'make coverage' in the fuzz/ directory
# 2. execute './view-coverage.sh <fuzz target(s)>

# Example with single fuzzer:
#   ./view-coverage.sh gnutls_client_fuzzer

# Example with two fuzzers:
#   ./view-coverage.sh gnutls_base64_decoder_fuzzer gnutls_base64_encoder_fuzzer

if test -z "$1"; then
  echo "Usage: $0 <fuzz target(s)>"
  echo "Example: $0 gnutls_client_fuzzer"
  exit 1
fi

LCOV_INFO=coverage.info
lcov --zerocounters --directory ../lib/
lcov --capture --initial --directory ../lib/.libs --directory . --output-file $LCOV_INFO
make check TESTS="$*" CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
lcov --capture --directory ../lib/.libs --output-file $LCOV_INFO
genhtml --prefix . --ignore-errors source $LCOV_INFO --legend --title "$*" --output-directory=lcov
xdg-open lcov/index.html
