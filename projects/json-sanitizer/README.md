# json-sanitizer

Given JSON-like content, The JSON Sanitizer converts it to valid JSON.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-json-sanitizer .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/json-sanitizer` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-json-sanitizer /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c DenylistFuzzer.toml run
    # sydr-fuzz -c IdempotenceFuzzer.toml run
    # sydr-fuzz -c ValidJsonFuzzer.toml run

Minimize corpus:

    # sydr-fuzz -c DenylistFuzzer.toml cmin

Collect and report coverage:

    # sydr-fuzz -c DenylistFuzzer.toml cov-html -s /json-sanitizer/src/main/java
