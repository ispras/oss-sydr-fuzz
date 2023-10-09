# OpenJPEG

OpenJPEG is an open-source JPEG 2000 codec written in C language.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-openjpeg .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/openjpeg` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-openjpeg /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c opj_decompress_fuzzer_J2K.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c opj_decompress_fuzzer_J2K-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c opj_decompress_fuzzer_J2K.toml cmin

Collect coverage:

    # sydr-fuzz -c opj_decompress_fuzzer_J2K.toml cov-export -- -format=lcov > opj_decompress_fuzzer_J2K.lcov
    # genhtml -o opj_decompress_fuzzer_J2K-html opj_decompress_fuzzer_J2K.lcov

Check security predicates:

    # sydr-fuzz -c opj_decompress_fuzzer_J2K.toml security

Supported fuzz targets:

    * opj_decompress_fuzzer_J2K
    * opj_decompress_fuzzer_JP2
