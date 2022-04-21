# zlib

zlib (zeta-lib) is a C library used for data compression.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-zlib .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/zlib` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-zlib /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### Fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c checksum_fuzzer.toml run

Collect and report coverage:

    # sydr-fuzz -c checksum_fuzzer.toml cov-report
