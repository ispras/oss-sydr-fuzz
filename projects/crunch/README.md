# Crunch

Crunch is a tool for lossy PNG image file optimization.

## Fuzz tagrets:

  * optimize_png
  * main_single_file 

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-crunch .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/crunch` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-crunch /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### optimize_png

Run fuzzing:

    # sydr-fuzz -c optimize_png.toml run

Minimize corpus:

    # sydr-fuzz -c optimize_png.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c optimize_png.toml pycov html

### main_single_file

Run fuzzing:

    # sydr-fuzz -c main_single_file.toml run

Minimize corpus:

    # sydr-fuzz -c main_single_file.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c main_single_file.toml pycov html
