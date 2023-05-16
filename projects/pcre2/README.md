# pcre2

The PCRE2 library is a set of C functions that implement regular expression pattern matching using the same syntax and semantics as Perl 5.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-pcre2 .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/pcre2` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-pcre2 /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c pcre2.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c pcre2-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c pcre2.toml cmin

Collect coverage:

    # sydr-fuzz -c pcre2.toml cov-export -- -format=lcov > pcre2.lcov
    # genhtml -o pcre2 pcre2.lcov

Check security predicates:

    # sydr-fuzz -c pcre2.toml security
