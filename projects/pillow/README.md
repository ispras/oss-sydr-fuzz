# Pillow

Pillow is the friendly PIL fork. PIL is the Python Imaging Library.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-pillow .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/pillow` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-pillow /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

## Fuzz tagrets:

  * pillow
  * font

## Fuzzing

### pillow

Run fuzzing:

    # sydr-fuzz -c pillow.toml run

Minimize corpus:

    # sydr-fuzz -c pillow.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c pillow.toml pycov html

### font

Run fuzzing:

    # sydr-fuzz -c font.toml run

Minimize corpus:

    # sydr-fuzz -c font.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c font.toml pycov html
