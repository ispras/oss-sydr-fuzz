# OpenCV

OpenCV (Open Source Computer Vision Library) is a C/C++ Library of algorithms for computer vision, image processing and general-purpose numerical algorithms with open source.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-opencv .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/opencv` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-opencv /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### Fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c core.toml run

Minimize corpus:

    # sydr-fuzz -c core.toml cmin

Collect and report coverage:

    # sydr-fuzz -c core.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c core.toml cov-export -- -format=lcov > core.lcov
    # genhtml -o core-html core.lcov

Similary for other fuzz tagrets.

Fuzz tagrets:

  * core
  * filestorage_read_file
  * filestorage_read_filename
  * filestorage_read_string
  * generateusergallerycollage
  * imdecode
  * imencode
  * imread