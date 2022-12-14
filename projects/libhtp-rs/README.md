# libhtp-rs

Experimental c2rust conversion of OISF/libhtp

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libhtp-rs .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libhtp-rs` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libhtp-rs /bin/bash

Change directory to `/fuzz`:

    $ cd /fuzz

Run hybrid fuzzing with libfuzzer:

    $ sydr-fuzz -c sydr-fuzz.toml run

Run hybrid fuzzing with afl++:

    $ sydr-fuzz -c sydr-fuzz-afl++.toml run

Minimize corpus:

    $ sydr-fuzz -c sydr-fuzz.toml cmin

Check security predicates:

    $ sydr-fuzz -c sydr-fuzz.toml security

Get coverage report:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libhtp-rs /bin/bash /fuzz/cover.sh /fuzz/sydr-fuzz-afl++-out/corpus

## Supported Targets

    * fuzz_htp