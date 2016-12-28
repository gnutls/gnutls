# Fuzzers

These are fuzzers designed for use with `libFuzzer`. Currently they are
primarily run on Google's OSS-Fuzz (https://github.com/google/oss-fuzz/).

OSS-Fuzz will automatically locate and compile any `*_fuzzer.cc` files and
assume they are fuzzers it should run.

The initial values for each parser fuzzer are taken from the $NAME.in
directory.
