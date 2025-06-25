# libheif

libheif is an implementation of the h.265 video codec. It is written from scratch and has a plain C API to enable a simple integration into other software.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libheif .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libjpeg` directory:

    $ unzip sydr.zip

Run docker:

```
   $ sudo docker run --rm -it -v "$PWD/":/fuzzing oss-sydr-fuzz-libheif /bin/bash
```

Change directory:

    # cd ../fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c config/sydr/file_fuzzer.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz -c file_fuzzer.toml cov-export -- -format=lcov > compress.lcov
    # genhtml -o compress-html compress.lcov

## Alternative Fuzz Targets

libjpeg project has more fuzz targets.

### sydr

    # sydr-fuzz -c config/sydr/file_fuzzer.toml run
    # sydr-fuzz -c config/sydr/box_fuzzer.toml run
    # sydr-fuzz -c config/sydr/color_conversion_fuzzer.toml run
    # sydr-fuzz -c config/sydr/encoder_fuzzer.toml run


### afl++

    # sydr-fuzz -c config/afl++/file_fuzzer_afl++.toml run
    # sydr-fuzz -c config/afl++/box_fuzzer_afl++.toml run
    # sydr-fuzz -c config/afl++/color_conversion_fuzzer_afl++.toml run
    # sydr-fuzz -c config/afl++/encoder_fuzzer_afl++.toml run

### Honggfuzz

    # sydr-fuzz -c config/hfuzz/file_fuzzer_hfuzz.toml run
    # sydr-fuzz -c config/hfuzz/box_fuzzer_hfuzz.toml run
    # sydr-fuzz -c config/hfuzz/color_conversion_fuzzer_hfuzz.toml run
    # sydr-fuzz -c config/hfuzz/encoder_fuzzer_hfuzz.toml run    

