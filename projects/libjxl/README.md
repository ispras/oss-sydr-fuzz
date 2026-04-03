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

    # sydr-fuzz -c transforms-lf.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz -c transforms-lf.toml cov-export -- -format=lcov > transforms.lcov
    # genhtml -o transforms-html transforms.lcov

## Alternative Fuzz Targets

libjxl project has 10 fuzz targets.

### transforms_fuzzer

    # sydr-fuzz -c transforms-lf.toml run

### color_encoding_fuzzer

    # sydr-fuzz -c color-encoding-lf.toml run

### fields_fuzzer

    # sydr-fuzz -c fields-lf.toml run

### icc_codec_fuzzer

    # sydr-fuzz -c icc-codec-lf.toml run

### djxl_fuzzer

    # sydr-fuzz -c djxl-lf.toml run

### cjxl_fuzzer

    # sydr-fuzz -c cjxl-lf.toml run

### decode_basic_info_fuzzer

    # sydr-fuzz -c decode-basic-info-lf.toml run

### rans_fuzzer

    # sydr-fuzz -c rans-lf.toml run

### set_from_bytes_fuzzer

    # sydr-fuzz -c set-from-bytes-lf.toml run

### streaming_fuzzer

    # sydr-fuzz -c streaming-lf.toml run