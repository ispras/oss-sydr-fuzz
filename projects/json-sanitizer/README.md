# json-sanitizer

Given JSON-like content, The JSON Sanitizer converts it to valid JSON.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-json-sanitizer .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/json-sanitizer` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-json-sanitizer /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c DenylistFuzzerJZ.toml run
    # sydr-fuzz -c IdempotenceFuzzerJZ.toml run
    # sydr-fuzz -c ValidJsonFuzzerJZ.toml run

    # sydr-fuzz -c DenylistFuzzerJF.toml run
    # sydr-fuzz -c IdempotenceFuzzerJF.toml run
    # sydr-fuzz -c ValidJsonFuzzerJF.toml run

Crash analysis:

    # sydr-fuzz -c DenylistFuzzerJZ.toml casr
    # sydr-fuzz -c IdempotenceFuzzerJZ.toml casr
    # sydr-fuzz -c ValidJsonFuzzerJZ.toml casr

    # sydr-fuzz -c DenylistFuzzerJF.toml casr
    # sydr-fuzz -c IdempotenceFuzzerJF.toml casr
    # sydr-fuzz -c ValidJsonFuzzerJF.toml casr

Minimize corpus (only for Jazzer):

    # sydr-fuzz -c DenylistFuzzer.toml cmin

Collect and report coverage (only for Jazzer):

    # sydr-fuzz -c DenylistFuzzer.toml cov-html
