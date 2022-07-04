# SQLite3

SQLite is a C-language library that implements a small, fast, self-contained,
high-reliability, full-featured, SQL database engine.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-sqlite3 .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/sqlite3` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-sqlite3 /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run

Collect and report coverage:

    # sydr-fuzz cov-report

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c sydr-fuzz-afl++.toml run
