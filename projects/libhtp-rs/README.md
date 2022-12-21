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

    $ sydr-fuzz -c htp.toml run

Run hybrid fuzzing with afl++:

    $ sydr-fuzz -c htp-afl++.toml run

Minimize corpus:

    $ sydr-fuzz -c htp-fuzz-afl++.toml cmin

Check security predicates:

    $ sydr-fuzz -c htp-fuzz-afl++.toml security

Get coverage report:

    $ sydr-fuzz -c htp-fuzz-afl++.toml cov-export -- -format=lcov > htp.lcov
    $ genhtml --ignore-errors source -o htp_html htp.lcov

## Supported Targets

    * fuzz_htp