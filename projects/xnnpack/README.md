# xnnpack

xnnpack is a high-efficiency floating-point and quantized neural network inference library.

## Fuzz targets

  * fuzz_model

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-xnnpack .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/xnnpack` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-xnnpack /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c fuzz_model-lf.toml run

Minimize corpus:

    # sydr-fuzz -c fuzz_model-lf.toml cmin

Check security predicates:

    # sydr-fuzz -c fuzz_model-lf.toml security

Crash triage with CASR:

    # sydr-fuzz -c fuzz_model-lf.toml casr

Get LCOV HTML coverage report:

    # sydr-fuzz -c fuzz_model-lf.toml cov-export -- -format=lcov > fuzz_model.lcov
    # genhtml -o fuzz_model-html fuzz_model.lcov

## Alternative Fuzz Targets

xnnpack project has 1 fuzz target.

### libfuzzer

    # sydr-fuzz -c fuzz_model-lf.toml run

### afl++

    # sydr-fuzz -c fuzz_model-afl++.toml run