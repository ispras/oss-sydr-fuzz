# libjxl

libjxl is the reference implementation of the JPEG XL image format.
JPEG XL is a modern image format with superior compression and quality
compared to legacy JPEG, supporting HDR, wide color gamut, and animation.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libjxl .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libjxl` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libjxl /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c tomls/lf/transforms-lf.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz -c tomls/lf/transforms-lf.toml cov-export -- -format=lcov > transforms.lcov
    # genhtml -o transforms-html transforms.lcov

## Alternative Fuzz Targets

libjxl project has 10 fuzz targets.

### libfuzzer

    # sydr-fuzz -c tomls/lf/transforms-lf.toml run
    # sydr-fuzz -c tomls/lf/color_encoding-lf.toml run
    # sydr-fuzz -c tomls/lf/fields-lf.toml run
    # sydr-fuzz -c tomls/lf/icc_codec-lf.toml run
    # sydr-fuzz -c tomls/lf/djxl-lf.toml run
    # sydr-fuzz -c tomls/lf/cjxl-lf.toml run
    # sydr-fuzz -c tomls/lf/decode_basic_info-lf.toml run
    # sydr-fuzz -c tomls/lf/rans-lf.toml run
    # sydr-fuzz -c tomls/lf/set_from_bytes-lf.toml run
    # sydr-fuzz -c tomls/lf/streaming-lf.toml run

### afl++

    # sydr-fuzz -c tomls/afl/transforms-afl.toml run
    # sydr-fuzz -c tomls/afl/color_encoding-afl.toml run
    # sydr-fuzz -c tomls/afl/fields-afl.toml run
    # sydr-fuzz -c tomls/afl/icc_codec-afl.toml run
    # sydr-fuzz -c tomls/afl/djxl-afl.toml run
    # sydr-fuzz -c tomls/afl/cjxl-afl.toml run
    # sydr-fuzz -c tomls/afl/decode_basic_info-afl.toml run
    # sydr-fuzz -c tomls/afl/rans-afl.toml run
    # sydr-fuzz -c tomls/afl/set_from_bytes-afl.toml run
    # sydr-fuzz -c tomls/afl/streaming-afl.toml run