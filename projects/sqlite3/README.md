# SQLite3

SQLite is a C-language library that implements a small, fast, self-contained,
high-reliability, full-featured, SQL database engine.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-sqlite3 .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/sqlite3` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --network host --rm -it -v $PWD:/fuzz oss-sydr-fuzz-sqlite3 /bin/bash

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus /fuzz/corpus

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run -l debug --log-file sydr-fuzz.log
