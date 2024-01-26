# libpng

libpng (Portable Network Graphics library) is a C Library for handling PNG images.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libpng .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libpng` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libpng /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### Fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c libpng_read.toml run

Collect and report coverage:

    # sydr-fuzz -c libpng_read.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c libpng_read.toml cov-export -- -format=lcov > libpng_read.lcov
    # genhtml -o libpng_read-html libpng_read.lcov

### Hybrid fuzzing with AFL++

    # sydr-fuzz -c libpng_read-afl++.toml run

## Alternative Fuzz Targets

libpng project has 2 fuzz targets

### read

    # sydr-fuzz -c libpng_read.toml run

### simple\_read

    # sydr-fuzz -c libpng_simple_read.toml run
