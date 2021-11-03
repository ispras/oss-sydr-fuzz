# libdwarf

A library for reading DWARF2 and later DWARF.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libdwarf .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libdwarf` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libdwarf /bin/bash

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus /fuzz/corpus

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run -l debug
