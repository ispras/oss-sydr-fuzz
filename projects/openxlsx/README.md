# OpenXLSX

OpenXLSX is a C++ library for reading, writing, creating and modifying Microsoft
Excel® files, with the .xlsx format.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-openxlsx .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/openxlsx` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-openxlsx /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run
