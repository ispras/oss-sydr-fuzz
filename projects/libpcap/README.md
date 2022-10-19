# Libpcap

Libpcap provides a portable framework for low-level network monitoring.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libpcap .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libpcap` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libpcap /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c filter.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c filter-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c filter.toml cmin

Collect coverage:

    # sydr-fuzz -c filter.toml cov-export -- -format=lcov > filter.lcov
    # genhtml -o filter-html filter.lcov

Check security predicates:

    # sydr-fuzz -c filter.toml security

Supported fuzz targets:

    * filter
    * pcap
