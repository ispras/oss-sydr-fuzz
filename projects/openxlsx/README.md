# OpenXLSX

OpenXLSX is a C++ library for reading, writing, creating and modifying Microsoft
Excel® files, with the .xlsx format.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-openxlsx .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/openxlsx` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-openxlsx /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run

Minimize corpus:

    # sydr-fuzz cmin

Collect and report coverage:

    # sydr-fuzz cov-report

## Hybrid fuzzing with AFL++

    # sydr-fuzz -c sydr-fuzz-afl++.toml run
