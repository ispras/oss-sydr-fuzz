# Image-rs/image

This crate provides basic image processing functions and methods for converting
to and from various image formats.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-image-rs .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/openssl` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-image-rs /bin/bash

### Prepare initial corpus

You could find initial seeds in image repo and copy them to `/fuzz/corpus`
directory. Example for tiff parser:

    # mkdir /fuzz/corpus && find /image -name "*.tiff" -exec cp {} /fuzz/corpus \;

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c tiff.toml run -l debug

## Alternative Fuzz Targets

Image-rs/image project has 12 fuzz targets.

### bmp

    # cd /fuzz
    # sydr-fuzz -c bmp.toml run -l debug

### exr

    # cd /fuzz
    # sydr-fuzz -c exr.toml run -l debug

### gif

    # cd /fuzz
    # sydr-fuzz -c gif.toml run -l debug

### guess

    # cd /fuzz
    # sydr-fuzz -c guess.toml run -l debug

### hdr

    # cd /fuzz
    # sydr-fuzz -c hdr.toml run -l debug

### ico

    # cd /fuzz
    # sydr-fuzz -c ico.toml run -l debug

### jpeg

    # cd /fuzz
    # sydr-fuzz -c jpeg.toml run -l debug

### png

    # cd /fuzz
    # sydr-fuzz -c png.toml run -l debug

### pnm

    # cd /fuzz
    # sydr-fuzz -c pnm.toml run -l debug

### tga

    # cd /fuzz
    # sydr-fuzz -c tga.toml run -l debug

### tiff

    # cd /fuzz
    # sydr-fuzz -c tiff.toml run -l debug

### webp

    # cd /fuzz
    # sydr-fuzz -c webp.toml run -l debug
