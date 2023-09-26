# suricata

Suricata is a network Intrusion Detection System, Intrusion Prevention System and Network Security Monitoring engine developed by the OISF and the Suricata community.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-suricata .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/suricata` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-suricata /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c fuzz_http1.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c fuzz_http1-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c fuzz_http1.toml cmin

Collect coverage:

    # sydr-fuzz -c fuzz_http1.toml cov-export -- -format=lcov > http1.lcov
    # genhtml -o http1 http1.lcov

Check security predicates:

    # sydr-fuzz -c fuzz_http1.toml security

## Supported Targets

    * fuzz_applayerparserparse_<proto>
    * fuzz_applayerprotodetectgetproto
    * fuzz_mimedecparseline
    * fuzz_predefpcap_aware
    * fuzz_sigpcap_aware
