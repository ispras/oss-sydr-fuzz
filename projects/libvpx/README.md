# libvpx

libvpx is a free software video codec library from Google and the Alliance for Open Media (AOMedia).

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libvpx .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libvpx` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libvpx /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c vpx_dec_fuzzer_vp8.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c vpx_dec_fuzzer_vp8-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c vpx_dec_fuzzer_vp8.toml cmin

Collect coverage:

    # sydr-fuzz -c vpx_dec_fuzzer_vp8.toml cov-export -- -format=lcov > vp8.lcov
    # genhtml -o vp8 vp8.lcov

Check security predicates:

    # sydr-fuzz -c vpx_dec_fuzzer_vp8.toml security

## Supported Targets

    * vpx_dec_fuzzer_vp8 
    * vpx_dec_fuzzer_vp9
