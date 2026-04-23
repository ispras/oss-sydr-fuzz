# brotli

Brotli compression format

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-brotli .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/brotli` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-brotli /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libFuzzer:

    # sydr-fuzz -c decode-lf.toml run

Run hybrid fuzzing with AFL++:

    # sydr-fuzz -c decode-afl++.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz -c decode-lf.toml cov-export -- -format=lcov > decode.lcov
    # genhtml -o decode-html decode.lcov
