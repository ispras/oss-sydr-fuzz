# HSQLDB

HSQLDB (HyperSQL DataBase) is the leading SQL relational database system written in Java. 

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-hsqldb .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/hsqldb` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-hsqldb /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c ConnectionOptionsFuzzer.toml run
    # sydr-fuzz -c SqlPreparedStatementFuzzer.toml run
    # sydr-fuzz -c SqlStatementFuzzer.toml run

Minimize corpus:

    # sydr-fuzz -c SqlStatementFuzzer.toml cmin

Collect and report coverage:

    # sydr-fuzz -c SqlStatementFuzzer.toml cov-html -s /hsqldb-svn/src
