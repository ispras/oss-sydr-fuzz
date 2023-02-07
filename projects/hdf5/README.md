# HDF5

HDF5 is a high-performace library implementing HDF5 file format.

## Build docker

    $ sudo docker build -t oss-sydr-fuzz-hdf5 .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/hdf5` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-hdf5 /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run

Minimize corpus:

    # sydr-fuzz cmin

Get LCOV HTML coverage report:

    # sydr-fuzz cov-export -- -format=lcov > hdf5.lcov
    # genhtml -o hdf5-html hdf5.lcov

## Hybrid Fuzzing with AFL++:

    # sydr-fuzz -c sydr-fuzz-afl++.toml run
