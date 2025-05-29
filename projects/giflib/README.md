# giflib

giflib is a library for manipulating GIF files.

## Build LibAFL-DiFuzz Docker

    $ sudo docker build --build-arg BASE_IMAGE="LIBAFL_DOCKER_NAME" -t oss-sydr-fuzz-libafl-giflib -f ./Dockerfile_libafl .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/giflib` directory:

    $ unzip sydr.zip

Run docker for LibAFL-DiFuzz:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libafl-giflib /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with LibAFL-DiFuzz:

    # sydr-fuzz -c giflib-libafl.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz cov-export -- -format=lcov > giflib.lcov
    # genhtml -o giflib-html giflib.lcov
