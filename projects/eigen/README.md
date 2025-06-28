# Eigen

Eigen is a C++ template library for linear algebra: matrices, vectors, numerical solvers, and related algorithms.

For more information go to http://eigen.tuxfamily.org/ or https://libeigen.gitlab.io/docs/.


## Build docker

    $ sudo docker build -t oss-sydr-fuzz-eigen .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/eigen` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-eigen /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c basicstuff-lf.toml run

Minimize corpus:

    # sydr-fuzz -c basicstuff-lf.toml cmin

Check security predicates:

    # sydr-fuzz -c basicstuff-lf.toml security

Crash triage with CASR:

    # sydr-fuzz -c basicstuff-lf.toml casr

Get LCOV HTML coverage report:

    # sydr-fuzz -c basicstuff-lf.toml cov-export -- -format=lcov > eigen.lcov
    # genhtml -o eigen-html eigen.lcov

## Hybrid Fuzzing with AFL++:

    # sydr-fuzz -c basicstuff-afl++.toml run

## Alternative Fuzz Targets

eigen has 2 fuzz targets, so you may run same commands with solver-lf.toml and solver-afl++.toml