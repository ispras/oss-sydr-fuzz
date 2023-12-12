# xlnt

xlnt is a modern C++ library for manipulating spreadsheets in memory and reading/writing them from/to XLSX files as described in ECMA 376 4th edition.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-xlnt .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/xlnt` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-xlnt /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run

Get LCOV HTML coverage report:

    # sydr-fuzz cov-export -- -format=lcov > load.lcov
    # genhtml -o load-html load.lcov

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c load-afl++.toml run

## Alternative Fuzz Targets

xlnt project has 2 fuzz targets.

### load

    # sydr-fuzz -c load.toml run

### save

    # sydr-fuzz -c save.toml run
