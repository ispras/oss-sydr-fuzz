# woff2

woff2 is a C library for converting woff2 files into ttf and back.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-woff2 .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/woff2` directory:

    $ unzip sydr.zip

## Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-woff2 /bin/bash

## Change directory to `/fuzz`:

    # cd /fuzz

## Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c convert_woff2ttf_fuzzing.toml run

## Minimize corpus:

    # sydr-fuzz -c convert_woff2ttf_fuzzing.toml cmin

## Check security predicates:

    # sydr-fuzz -c convert_woff2ttf_fuzzing.toml security

## Crash triage with CASR:

    # sydr-fuzz -c convert_woff2ttf_fuzzing.toml casr

## Get LCOV HTML coverage report:

    # sydr-fuzz -c convert_woff2ttf_fuzzing.toml cov-html

## Run hybrid fuzzing with afl++:

    # sydr-fuzz -c convert_woff2ttf_fuzzing-afl++.toml run

## Alternative Fuzz Targets

woff2 project has 2 alternative fuzz targets.

### convert_woff2ttf_fuzzing

    # sydr-fuzz -c convert_woff2ttf_fuzzing.toml run

### convert_woff2ttf_fuzzing_new_entry

    # sydr-fuzz -c convert_woff2ttf_fuzzing_new_entry.toml run

