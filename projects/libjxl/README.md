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

    # sydr-fuzz -c tomls/transforms-lf.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz -c tomls/transforms-lf.toml cov-export -- -format=lcov > transforms.lcov
    # genhtml -o transforms-html transforms.lcov

## Alternative Fuzz Targets

libjxl project has 10 fuzz targets.

### libfuzzer

    # sydr-fuzz -c tomls/transforms-lf.toml run
    # sydr-fuzz -c tomls/color_encoding-lf.toml run
    # sydr-fuzz -c tomls/fields-lf.toml run
    # sydr-fuzz -c tomls/icc_codec-lf.toml run
    # sydr-fuzz -c tomls/djxl-lf.toml run
    # sydr-fuzz -c tomls/cjxl-lf.toml run
    # sydr-fuzz -c tomls/decode_basic_info-lf.toml run
    # sydr-fuzz -c tomls/rans-lf.toml run
    # sydr-fuzz -c tomls/set_from_bytes-lf.toml run
    # sydr-fuzz -c tomls/streaming-lf.toml run

### afl++

    # sydr-fuzz -c tomls/transforms-afl++.toml run
    # sydr-fuzz -c tomls/color_encoding-afl++.toml run
    # sydr-fuzz -c tomls/fields-afl++.toml run
    # sydr-fuzz -c tomls/icc_codec-afl++.toml run
    # sydr-fuzz -c tomls/djxl-afl++.toml run
    # sydr-fuzz -c tomls/cjxl-afl++.toml run
    # sydr-fuzz -c tomls/decode_basic_info-afl++.toml run
    # sydr-fuzz -c tomls/rans-afl++.toml run
    # sydr-fuzz -c tomls/set_from_bytes-afl++.toml run
    # sydr-fuzz -c tomls/streaming-afl++.toml run