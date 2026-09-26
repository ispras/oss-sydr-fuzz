# elfutils

elfutils is a collection of libraries and command-line tools for inspecting, analyzing, and manipulating ELF binaries and DWARF debugging information.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-elfutils .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/elfutils` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-elfutils /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### libfuzzer

Run hybrid fuzzing:

    # sydr-fuzz -c tomls/dwfl-core-lf.toml run

Minimize corpus:

    # sydr-fuzz -c tomls/dwfl-core-lf.toml cmin

Collect coverage:

    # sydr-fuzz -c tomls/dwfl-core-lf.toml cov-html

Check security predicates:

    # sydr-fuzz -c tomls/dwfl-core-lf.toml security

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c tomls/dwfl-core-afl++.toml run

## Hybrid Fuzzing with LibAFL-DiFuzz

    # sydr-fuzz -c tomls/dwfl-core-libafl.toml run

## Alternative Fuzz Targets

### libfuzzer

    # sydr-fuzz -c tomls/dwfl-core-lf.toml run
    # sydr-fuzz -c tomls/libdwfl-lf.toml run
    # sydr-fuzz -c tomls/libelf-lf.toml run

### afl++

    # sydr-fuzz -c tomls/dwfl-core-alf++.toml run
    # sydr-fuzz -c tomls/libdwfl-afl++.toml run
    # sydr-fuzz -c tomls/libelf-lf.toml run

  ### LibAFL-DiFuzz

    # sydr-fuzz -c tomls/dwfl-core-libafl.toml run
    # sydr-fuzz -c tomls/libdwfl-libafl.toml run
    # sydr-fuzz -c tomls/libelf-libafl.toml run
