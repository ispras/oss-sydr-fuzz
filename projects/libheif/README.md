# libheif

libheif is an implementation of the h.265 video codec. It is written from scratch and has a plain C API to enable a simple integration into other software.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libheif .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libjpeg` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libjpeg /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c compress.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz -c compress.toml cov-export -- -format=lcov > compress.lcov
    # genhtml -o compress-html compress.lcov

## Alternative Fuzz Targets

libjpeg project has 2 fuzz targets.

### compress

    # sydr-fuzz -c compress.toml run

### decompress

    # sydr-fuzz -c decompress.toml run

