# libxml2

libxml2 is an XML toolkit implemented in C, originally developed for the GNOME Project.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libxml2 .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libxml2` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libxml2 /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c fuzz_xml.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c fuzz_xml-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c fuzz_xml.toml cmin

Collect coverage:

    # sydr-fuzz -c fuzz_xml.toml cov-export -- -format=lcov > xml.lcov
    # genhtml -o xml xml.lcov

Check security predicates:

    # sydr-fuzz -c fuzz_xml.toml security

## Supported Targets

    * xml
    * html
    * uri
    * regexp
    * schema
    * xinclude
    * xpath
