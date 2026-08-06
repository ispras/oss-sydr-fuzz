# CPython3

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

    # sydr-fuzz -c tomls/lf.toml run

Minimize corpus:

    # sydr-fuzz -c tomls/lf.toml cmin

Collect coverage:

    # sydr-fuzz -c tomls/lf.toml cov-export -- -format=lcov > cpp-httplib.lcov
    # genhtml -o cpp-httplib cpp-httplib.lcov

Check security predicates:

    # sydr-fuzz -c tomls/lf.toml security

### afl++
Same as in libfuzzer except different TOML

    # sydr-fuzz -c tomls/afl++.toml run

