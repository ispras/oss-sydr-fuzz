# Image-rs/image

This crate provides basic image processing functions and methods for converting
to and from various image formats.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-image-rs .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/image-rs` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-image-rs /bin/bash

### Prepare Initial Corpus

You could find initial seeds in image repo and copy them to `/fuzz/corpus`
directory. Example for tiff parser:

    # mkdir /fuzz/corpus && find /image -name "*.tiff" -exec cp {} /fuzz/corpus \;

### Run Fuzzing

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c tiff.toml run

Collect coverage:

    # sydr-fuzz -c tiff.toml cov-export -- -format=lcov > tiff.lcov
    # genhtml --ignore-errors source -o tiff_html tiff.lcov

## Alternative Fuzz Targets

Image-rs/image project has 12 fuzz targets.

### bmp

    # cd /fuzz
    # sydr-fuzz -c bmp.toml run

### exr

    # cd /fuzz
    # sydr-fuzz -c exr.toml run

### gif

    # cd /fuzz
    # sydr-fuzz -c gif.toml run

### guess

    # cd /fuzz
    # sydr-fuzz -c guess.toml run

### hdr

    # cd /fuzz
    # sydr-fuzz -c hdr.toml run

### ico

    # cd /fuzz
    # sydr-fuzz -c ico.toml run

### jpeg

    # cd /fuzz
    # sydr-fuzz -c jpeg.toml run

### png

    # cd /fuzz
    # sydr-fuzz -c png.toml run

### pnm

    # cd /fuzz
    # sydr-fuzz -c pnm.toml run

### tga

    # cd /fuzz
    # sydr-fuzz -c tga.toml run

### tiff

    # cd /fuzz
    # sydr-fuzz -c tiff.toml run

### webp

    # cd /fuzz
    # sydr-fuzz -c webp.toml run

### AFL++ fuzz targets

    # cd /fuzz
    # sydr-fuzz -c <name>-afl++.toml run
