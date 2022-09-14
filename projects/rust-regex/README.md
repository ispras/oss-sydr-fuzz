# regex

A Rust library for parsing, compiling, and executing regular expressions. Its
syntax is similar to Perl-style regular expressions, but lacks a few features
like look around and backreferences.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-regex .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/regex` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-regex /bin/bash

### Run Fuzzing

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c regex_match.toml run
