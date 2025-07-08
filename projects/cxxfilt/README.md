# cxxfilt

cxxfilt is a tool for demangling C++ symbols.

## Build LibAFL-DiFuzz Docker

Pass `sydr.zip` as an argument:

    $ sudo docker build --build-arg SYDR_ARCHIVE="sydr.zip" -t oss-sydr-fuzz-libafl-cxxfilt -f ./Dockerfile_libafl .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/cxxfilt` directory:

    $ unzip sydr.zip

Run docker for LibAFL-DiFuzz:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libafl-cxxfilt /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with LibAFL-DiFuzz:

    # sydr-fuzz -c cxxfilt-libafl.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz cov-export -- -format=lcov > cxxfilt.lcov
    # genhtml -o cxxfilt-html cxxfilt.lcov
