# Rizin

Rizin is a fork of the radare2 reverse engineering framework.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-rizin .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/rizin` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-rizin /bin/bash

Run hybrid fuzzing with libFuzzer:

    # sydr-fuzz run

Or with AFL++:

    # sydr-fuzz -c sydr-fuzz-afl++.toml run

Collect and report coverage:

    # sydr-fuzz cov-report
