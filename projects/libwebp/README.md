# libwebp

WebP codec is a library to encode and decode images in WebP format.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libweb .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/xlnt` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libwebp /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c huffman.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz -c huffman.toml cov-html

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c huffman-afl++.toml run
