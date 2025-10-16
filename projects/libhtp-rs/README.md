# libhtp-rs

Experimental c2rust conversion of OISF/libhtp

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libhtp-rs .

## Build LibAFL-DiFuzz Docker

Pass `sydr.zip` as an argument:

    $ sudo docker build --build-arg SYDR_ARCHIVE="sydr.zip" -t oss-sydr-fuzz-libafl-libhtp-rs -f ./Dockerfile_libafl .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libhtp-rs` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libhtp-rs /bin/bash

Run docker for LibAFL-DiFuzz:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libafl-libhtp-rs /bin/bash

Change directory to `/fuzz`:

    $ cd /fuzz

Run hybrid fuzzing with libfuzzer:

    $ sydr-fuzz -c htp-lf.toml run

Run hybrid fuzzing with AFL++:

    $ sydr-fuzz -c htp-afl++.toml run

Run hybrid directed fuzzing with LibAFL-DiFuzz:

    $ sydr-fuzz -c htp-libafl.toml run

Minimize corpus:

    $ sydr-fuzz -c htp-afl++.toml cmin

Check security predicates:

    $ sydr-fuzz -c htp-afl++.toml security

Get coverage report:

    $ sydr-fuzz -c htp-afl++.toml cov-html

## Supported Targets

    * fuzz_htp
