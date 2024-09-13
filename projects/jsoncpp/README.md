# jsoncpp

A C++ library for interacting with JSON. 

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-jsoncpp .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/jsoncpp` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-jsoncpp /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c jsoncpp_fuzz.toml run

Minimize corpus:

    # sydr-fuzz -c jsoncpp_fuzz.toml cmin

Check security predicates:

    # sydr-fuzz -c jsoncpp_fuzz.toml security

Crash triage with CASR:

    # sydr-fuzz -c jsoncpp_fuzz.toml casr

Get LCOV HTML coverage report:

    # sydr-fuzz -c jsoncpp_fuzz.toml cov-html

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c jsoncpp_fuzz-afl++.toml run
