# FFmpeg

A complete, cross-platform solution to record, convert and stream audio and video.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-ffmpeg .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/ffmpeg` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-ffmpeg /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c target_bsf_fuzzer.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c target_bsf_fuzzer-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c target_bsf_fuzzer.toml cmin

Collect coverage:

    # sydr-fuzz -c target_bsf_fuzzer.toml cov-export -- -format=lcov > target_bsf_fuzzer.lcov
    # genhtml -o target_bsf_fuzzer-html target_bsf_fuzzer.lcov

Check security predicates:

    # sydr-fuzz -c target_bsf_fuzzer.toml security

Supported fuzz targets:

    * target_bsf_fuzzer
    * target_dem_fuzzer
    * target_dec_fuzzer
