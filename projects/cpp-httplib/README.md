# cpp-httplib

A C++11 single-file header-only cross platform HTTP/HTTPS library.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-cpp-httplib .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/cpp-httplib` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-cpp-httplib /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### libfuzzer
Run hybrid fuzzing:

    # sydr-fuzz -c tomls/server-lf.toml run

Minimize corpus:

    # sydr-fuzz -c tomls/server-lf.toml cmin

Collect coverage:

    # sydr-fuzz -c tomls/server-lf.toml cov-html

Check security predicates:

    # sydr-fuzz -c tomls/server-lf.toml security

## Alternative Fuzz Targets
### libfuzzer

    # sydr-fuzz -c tomls/server-lf.toml run
    # sydr-fuzz -c tomls/client-lf.toml run
    # sydr-fuzz -c tomls/header-parser-lf.toml run
    # sydr-fuzz -c tomls/url-parser-lf.toml run
    # sydr-fuzz -c tomls/multipart-parser-lf.toml run

### afl++

    # sydr-fuzz -c tomls/server-afl++.toml run
    # sydr-fuzz -c tomls/client-afl++.toml run
    # sydr-fuzz -c tomls/header-parser-afl++.toml run
    # sydr-fuzz -c tomls/url-parser-afl++.toml run
    # sydr-fuzz -c tomls/multipart-parser-afl++.toml run

