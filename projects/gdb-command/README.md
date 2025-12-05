# gdb-command

gdb-command is a library providing API for manipulating gdb in batch mode. It
supports:

* Execution of target program (Local type).
* Opening core of target program (Core type).
* Attaching to remote process (Remote type).

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-gdb-command .

## Build LibAFL-DiFuzz Docker

Pass `sydr.zip` as an argument:

    $ sudo docker build --build-arg SYDR_ARCHIVE="sydr.zip" -t oss-sydr-fuzz-libafl-gdb-command -f ./Dockerfile_libafl .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/gdb-command` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-gdb-command /bin/bash

Run docker for LibAFL-DiFuzz:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libafl-gdb-command /bin/bash

### Run Fuzzing

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c from_gdb-lf.toml run

Run hybrid fuzzing with AFL++:

    # sydr-fuzz -c from_gdb-afl++.toml run

Run hybrid directed fuzzing with LibAFL-DiFuzz:

    # sydr-fuzz -c from_gdb-libafl.toml run

Get coverage report:

    # sydr-fuzz -c from_gdb-lf.toml cov-html
