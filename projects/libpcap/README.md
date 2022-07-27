# libpcap

The Packet Capture library provides a high level interface to packet capture systems. 

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libpcap .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libpcap` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libpcap /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run

Get LCOV HTML coverage report:

    # sydr-fuzz cov-export -- -format=lcov > load.lcov
    # genhtml -o load-html load.lcov
