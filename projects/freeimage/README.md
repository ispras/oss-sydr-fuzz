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

    # sydr-fuzz -c load_from_memory.toml run

## Minimize corpus:

    # sydr-fuzz -c load_from_memory.toml cmin

## Check Security Predicates

Check security predicates on new corpus:

    # sydr-fuzz -c load_from_memory.toml security

## Alternative Fuzz Targets

FreeImage project has 2 fuzz targets.

### load_from_memory

    # sydr-fuzz -c load_from_memory.toml run

### load_from_memory_tiff

    # sydr-fuzz -c load_from_memory_tiff.toml run

### transform_combined_jpeg

    # sydr-fuzz -c transform_combined_jpeg.toml run
