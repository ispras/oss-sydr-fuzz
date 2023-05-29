# CPython3

Python3 Interpreter

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-cpython3 .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/cpython3` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-cpython3 /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_binascii_a2b.toml run

Minimize corpus:

    # sydr-fuzz -c fuzz_binascii_a2b.toml cmin

Collect coverage:

    # sydr-fuzz -c fuzz_binascii_a2b.toml cov-export -- -format=lcov > cpython3.lcov
    # genhtml -o cpython3 cpython3.lcov

Check security predicates:

    # sydr-fuzz -c fuzz_binascii_a2b.toml security

## Alternative Fuzz Targets
Project cpython have 11 fuzz targets listed in fuzzer_tests.txt:
+ fuzz_builtin_float - float(str)
+ fuzz_builtin_int - int(str)
+ fuzz_builtin_unicode - UTF8 encoder 
+ fuzz_json_loads - JSON parser
+ fuzz_sre_compile - Regex compiler
+ fuzz_sre_match - Regex searcher
+ fuzz_csv_reader - CSV reader
+ fuzz_struct_unpack 
+ fuzz_xml_parse - XML parser
+ fuzz_binascii_a2b - Base64 encoder
+ fuzz_codecs_encode - Encodings Encoder
