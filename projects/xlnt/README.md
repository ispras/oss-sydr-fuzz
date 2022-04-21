# xlnt

xlnt is a modern C++ library for manipulating spreadsheets in memory and reading/writing them from/to XLSX files as described in ECMA 376 4th edition.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-xlnt .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/xlnt` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-xlnt /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run

Get LCOV HTML coverage report:

    # sydr-fuzz cov-export -- -format=lcov > load.lcov
    # genhtml -o load-html load.lcov
