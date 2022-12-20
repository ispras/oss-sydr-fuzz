# Serde JSON

Serde is a framework for serializing and deserializing Rust data structures
efficiently and generically.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-serde-json .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/serde-json` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-serde-json /bin/bash

### Run Fuzzing

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c from_slice.toml run

Collect coverage:

    # sydr-fuzz -c from_slice.toml cov-export -- -format=lcov > from_slice.lcov
    # genhtml --ignore-errors source -o from_slice_html from_slice.lcov
