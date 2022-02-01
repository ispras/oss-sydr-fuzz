# libcbor

libcbor is a C library for parsing and generating CBOR, the general-purpose
schema-less binary data format.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libcbor .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libcbor` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libcbor /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run
