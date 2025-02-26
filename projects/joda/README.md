# Joda-Time

Joda-Time provides a quality replacement for the Java date and time classes.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-joda-time .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/joda-time` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-joda-time /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run fuzzing:

    # sydr-fuzz -c TimeFuzzer.toml run

Minimize corpus:

    # sydr-fuzz -c TimeFuzzer.toml cmin 

Collect and report coverage:

    # sydr-fuzz -c TimeFuzzer.toml cov-html -s /joda-time/src/main/java
