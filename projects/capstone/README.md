# Capstone Engine

Capstone is a disassembly framework with the target of becoming the ultimate
disasm engine for binary analysis and reversing in the security community.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-capstone .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/capstone` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-capstone /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_disasm.toml run

Minimize corpus:

    # sydr-fuzz -c fuzz_disasm.toml cmin

Check security predicates:

    # sydr-fuzz -c fuzz_disasm.toml security

Collect and report coverage:

    # sydr-fuzz -c fuzz_disasm.toml cov-report

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c fuzz_disasm-afl++.toml run
