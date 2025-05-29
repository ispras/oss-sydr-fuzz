# jasper

jasper is a library for manipulating JPEG 2000 images.

## Build LibAFL-DiFuzz Docker

    $ sudo docker build --build-arg BASE_IMAGE="LIBAFL_DOCKER_NAME" -t oss-sydr-fuzz-libafl-jasper -f ./Dockerfile_libafl .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/jasper` directory:

    $ unzip sydr.zip

Run docker for LibAFL-DiFuzz:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libafl-jasper /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with LibAFL-DiFuzz:

    # sydr-fuzz -c jasper-libafl.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz cov-export -- -format=lcov > jasper.lcov
    # genhtml -o jasper-html jasper.lcov
