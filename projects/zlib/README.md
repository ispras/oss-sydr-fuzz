# zlib

zlib (zeta-lib) is a C Library used for data compress.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-zlib .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/zlib` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-zlib /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### Fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c checksum.toml run

Collect and report coverage:

    # sydr-fuzz -c checksum.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c checksum.toml cov-export -- -format=lcov > checksum.lcov
    # genhtml -o checksum-html checksum.lcov

### Hybrid Fuzzing with AFL++

    # sydr-fuzz -c checksum-afl++.toml run

Similary for other fuzz tagrets.

Fuzz tagrets:

  * checksum
  * compress
  * example_dict
  * example_flush
  * example_large
  * example_small
  * minigzip
  * zlib_uncompress
  * zlib_uncompress2
