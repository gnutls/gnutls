# Fuzzers

These are fuzzers designed for use with `libFuzzer`. Currently they are
primarily run on Google's OSS-Fuzz (https://github.com/google/oss-fuzz/).

OSS-Fuzz will automatically locate and compile any `*_fuzzer.cc` files and
assume they are fuzzers it should run.

The initial values for each parser fuzzer are taken from the $NAME.in
directory.

# Reproducing a specific issue

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



