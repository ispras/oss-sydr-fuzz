# libcue

CUE Sheet Parser Library

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libcue .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libcue` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libcue /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c fuzz_cue_parse_string.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c fuzz_cue_parse_string-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c fuzz_cue_parse_string.toml cmin

Collect coverage:

    # sydr-fuzz -c fuzz_cue_parse_string.toml cov-export -- -format=lcov > cue.lcov
    # genhtml -o cue cue.lcov

Check security predicates:

    # sydr-fuzz -c fuzz_cue_parse_string.toml security

## Supported Targets

    * fuzz_cue_parse_string

