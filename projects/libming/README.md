# libming

libming is a Flash (SWF) output library.

## Build LibAFL-DiFuzz Docker

Pass `sydr.zip` as an argument:

    $ sudo docker build --build-arg SYDR_ARCHIVE="sydr.zip" -t oss-sydr-fuzz-libafl-libming -f ./Dockerfile_libafl .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libming` directory:

    $ unzip sydr.zip

Run docker for LibAFL-DiFuzz:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libafl-libming /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with LibAFL-DiFuzz:

    # sydr-fuzz -c libming-libafl.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz cov-export -- -format=lcov > libming.lcov
    # genhtml -o libming-html libming.lcov
