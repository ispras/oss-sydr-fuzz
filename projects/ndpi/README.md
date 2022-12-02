# nDPI

Open Source Deep Packet Inspection Software Toolkit

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-ndpi .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/ndpi` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-ndpi /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c process-packet.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c process-packet-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c process-packet.toml cmin

Collect coverage:

    # sydr-fuzz -c process-packet.toml cov-export -- -format=lcov > ndpi.lcov
    # genhtml -o ndpi ndpi.lcov

Check security predicates:

    # sydr-fuzz -c process-packet.toml security

## Supported Targets

    * process-packet
    * ndpi-reader
    * quic_get_crypto_data