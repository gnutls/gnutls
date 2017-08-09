# Fuzzers

These are fuzzers designed for use with `libFuzzer`. Currently they are
primarily run on Google's OSS-Fuzz (https://github.com/google/oss-fuzz/).

OSS-Fuzz will automatically locate and compile any `*_fuzzer.cc` files and
assume they are fuzzers it should run.

The initial values for each parser fuzzer are taken from the $NAME.in
directory.

The command "make update" will update the stored corpus/traces
using other projects like openssl.


# Running a fuzzer using AFL

Use the following commands on top dir:

```
$ CC="afl-gcc" ./configure --enable-fuzzer-target
$ make -j$(nproc)
$ cd devel/fuzz
$ make gnutls_pkcs7_parser_fuzzer
$ ./run-afl.sh gnutls_pkcs7_parser_fuzzer
```

This will execute AFL (which runs indefinitely until CTRL+C is pressed) and
provide its output in a "gnutls_pkcs7_parser_fuzzer.PID.out" directory.


# Reproducing a reported issue from oss-fuzz

Assuming an issue on the "gnutls_pkcs7_parser_fuzzer" was found, and the
reproducer is placed in $FILE, to reproduce locally use the following commands
on top dir:

```
$ CFLAGS="-fsanitize=address -g -O2" ./configure
$ make -j$(nproc)
$ cd devel/fuzz
$ make gnutls_pkcs7_parser_fuzzer
$ ./gnutls_pkcs7_parser_fuzzer <$FILE
```

Alternatively (if local reproduction is not possible), you can reproduce it
using the original docker instance used to find the issue as follows.

```
sudo docker run --rm -e ASAN_OPTIONS="detect_leaks=0" -ti -v $FILE:/testcase ossfuzz/gnutls reproduce gnutls_pkcs7_parser_fuzzer
```

# Enhancing the testsuite for issues found

For the following tests dropping a file to a subdirectory in tests is
sufficient:

| Fuzzer                       | Directory                   |
|:----------------------------:|:---------------------------:|
|gnutls_client_fuzzer          | tests/client-interesting    |
|gnutls_server_fuzzer          | tests/server-interesting    |
|gnutls_psk_client_fuzzer      | tests/psk-client-interesting|
|gnutls_psk_server_fuzzer      | tests/psk-server-interesting|
|gnutls_srp_client_fuzzer      | tests/srp-client-interesting|
|gnutls_srp_server_fuzzer      | tests/srp-server-interesting|
|gnutls_pkcs7_parser_fuzzer    | tests/pkcs7-interesting     |
|gnutls_x509_parser_fuzzer     | tests/certs-interesting     |
|gnutls_ocsp_resp_parser_fuzzer| tests/ocsp-resp-interesting |

The following require modifying a test case. Mappings are shown in the
table below.

| Fuzzer                          | Test case                                                |
|:-------------------------------:|:--------------------------------------------------------:|
|gnutls_dn_parser_fuzzer          |tests/x509-dn-decode.c                                    |
|gnutls_pkcs8_key_parser_fuzzer   |tests/key-tests/pkcs8-invalid,tests/key-tests/pkcs8-decode|
|gnutls_private_key_parser_fuzzer |tests/key-tests/key-invalid                               |


# Missing fuzzers

 * TLS resumption
 * TLS rehandshake
 * Fuzzying past finished message processing
