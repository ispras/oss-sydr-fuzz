# FreeImage

FreeImage is an Open Source library project for developers who would like to
support popular graphics image formats like PNG, BMP, JPEG, TIFF and others as
needed by today's multimedia applications.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-freeimage .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/freeimage` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run -v /etc/localtime:/etc/localtime:ro --privileged --network host --rm -it -v $PWD:/fuzz oss-sydr-fuzz-freeimage /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run -l debug
