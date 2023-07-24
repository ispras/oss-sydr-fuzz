# tcpdump

tcpdump is a data-network packet analyzer computer program that runs under a command line interface.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-tcpdump .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/tcpdump` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-tcpdump /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c pretty_print_packet.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c pretty_print_packet-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c pretty_print_packet.toml cmin

Collect coverage:

    # sydr-fuzz -c pretty_print_packet.toml cov-export -- -format=lcov > pretty_print_packet.lcov
    # genhtml -o pretty_print_packet-html pretty_print_packet.lcov

Check security predicates:

    # sydr-fuzz -c pretty_print_packet.toml security
