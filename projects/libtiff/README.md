# LibTIFF

LibTIFF is a library for reading and writing Tagged Image File Format (abbreviated TIFF) files.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libtiff .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libtiff` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libtiff /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### Fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c tiff_read_rgba.toml run

Collect and report coverage:

    # sydr-fuzz -c tiff_read_rgba.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c tiff_read_rgba.toml cov-export -- -format=lcov > tiff_read_rgba.lcov
    # genhtml -o tiff_read_rgba-html tiff_read_rgba.lcov

### Hybrid fuzzing with AFL++

    # sydr-fuzz -c tiff_read_rgba-afl++.toml run
