# RapidJSON

A fast JSON parser/generator for C++ with both SAX/DOM style API

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-rapidjson .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/rapidjson` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-rapidjson /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run

Collect and report coverage:

    # sydr-fuzz cov-report

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c sydr-fuzz-afl++.toml run
