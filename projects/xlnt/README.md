# xlnt

xlnt is a modern C++ library for manipulating spreadsheets in memory and reading/writing them from/to XLSX files as described in ECMA 376 4th edition.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-xlnt .

## Build LibAFL-DiFuzz Docker

    $ sudo docker --build-arg BASE_IMAGE="LIBAFL_DOCKER_NAME" build -t oss-sydr-fuzz-libafl-xlnt -f ./Dockerfile_libafl .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/xlnt` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-xlnt /bin/bash

Run docker for LibAFL-DiFuzz:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libafl-xlnt /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c load-lf.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz cov-export -- -format=lcov > load.lcov
    # genhtml -o load-html load.lcov

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c load-afl++.toml run

## Hybrid Fuzzing with HonggFuzz

    # sydr-fuzz -c load-hfuzz.toml run

## Hybrid Fuzzing with LibAFL-DiFuzz

    # sydr-fuzz -c load-libafl.toml run

## Alternative Fuzz Targets

xlnt project has 2 fuzz targets.

### load

    # sydr-fuzz -c load-lf.toml run

### save

    # sydr-fuzz -c save-lf.toml run
