# golang/image

This repository holds supplementary Go image libraries.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-image-go .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/image-go` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-image-go /bin/bash

### Run Fuzzing

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c tiff.toml run

## Alternative Fuzz Targets

golang/image project has 5 fuzz targets.

### gif

    # cd /fuzz
    # sydr-fuzz -c gif.toml run

### jpeg

    # cd /fuzz
    # sydr-fuzz -c jpeg.toml run

### png

    # cd /fuzz
    # sydr-fuzz -c png.toml run

### tiff

    # cd /fuzz
    # sydr-fuzz -c tiff.toml run

### webp

    # cd /fuzz
    # sydr-fuzz -c webp.toml run
