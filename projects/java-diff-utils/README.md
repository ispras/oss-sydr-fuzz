# java-diff-utils

Diff Utils library is an OpenSource library for performing the comparison operations between texts.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-java-diff-utils .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/java-diff-utils` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-java-diff-utils /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run fuzzing:

    # sydr-fuzz -c DiffUtilsFuzzer.toml run

Minimize corpus:

    # sydr-fuzz -c DiffUtilsFuzzer.toml cmin 

Collect and report coverage:

    # sydr-fuzz -c DiffUtilsFuzzer.toml cov-html -s /java-diff-util/java-diff-utils/src/main/java
