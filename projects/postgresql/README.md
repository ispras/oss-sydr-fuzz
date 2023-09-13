# PostgreSQL

PostgreSQL is an advanced object-relational database management system that
supports an extended subset of the SQL standard, including transactions, foreign
keys, subqueries, triggers, user-defined types and functions.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-postgresql .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/postgresql` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --name oss-sydr-fuzz-postgresql --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-postgresql /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c simple_query.toml run

Collect and report coverage:

    # sydr-fuzz -c simple_query.toml cov-report

## Alternative Fuzz Targets

PostgreSQL project has 2 fuzz targets.

### simple_query

    # sydr-fuzz -c simple_query.toml run

### json_parser

    # sydr-fuzz -c json_parser.toml run
