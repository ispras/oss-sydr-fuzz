# Torchvision

This library is part of the PyTorch project. PyTorch is an open source machine learning framework. The torchvision package consists of popular datasets, model architectures, and common image transformations for computer vision.

## Perfomance note

This project uses some performance related settings and you can tune this for your machine:

* `-rss_limit_mb=15360` in *.toml - Memory usage limit for libFuzzer (in Mb), default 15GB. Use 0 to disable the limit. If an input requires more than this amount of RSS memory to execute, the process is treated as a failure case. The limit is checked in a separate thread every second.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-vision .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/vision` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-vision /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### Fuzz Targets

#### decode_jpeg

Run hybrid fuzzing:

    # sydr-fuzz -c decode_jpeg.toml run

Minimize corpus:

    # sydr-fuzz -c decode_jpeg.toml cmin

#### decode_png

Run hybrid fuzzing:

    # sydr-fuzz -c decode_png.toml run

Minimize corpus:

    # sydr-fuzz -c decode_png.toml cmin

#### encode_jpeg

Run hybrid fuzzing:

    # sydr-fuzz -c encode_jpeg.toml run

Minimize corpus:

    # sydr-fuzz -c encode_jpeg.toml cmin

#### encode_png

Run hybrid fuzzing:

    # sydr-fuzz -c encode_png.toml run

Minimize corpus:

    # sydr-fuzz -c encode_png.toml cmin

### Fuzz Targets for AFL++

#### decode_jpeg-afl++

    # sydr-fuzz -c decode_jpeg-afl++.toml run

#### decode_png-afl++

    # sydr-fuzz -c decode_png-afl++.toml run

#### encode_jpeg-afl++

    # sydr-fuzz -c encode_jpeg-afl++.toml run

#### encode_png-afl++

    # sydr-fuzz -c encode_png-afl++.toml run

## Security predicates

    # sydr-fuzz -c <target_name>.toml security

## Crash analysis with Casr

    # sydr-fuzz -c <target_name>.toml casr
