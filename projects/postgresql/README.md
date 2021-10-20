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

    $ sudo docker run --name oss-sydr-fuzz-postgresql --network host --rm -it -v $PWD:/fuzz oss-sydr-fuzz-postgresql /bin/bash

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus /fuzz/corpus

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c simple_query.toml run -l debug --log-file sydr-fuzz.log

## Cleanup Temporary Databases During Fuzzing

New temporary databases are created for each Sydr run in `/tmp` directory. These
databases may exhaust the disk space. We should remove old databases.

Connect to docker:

    $ sudo docker exec -it oss-sydr-fuzz-postgresql /bin/bash

Run command that will minutely remove databases older than 10 minutes:

    # watch -n 60 "find /tmp -mmin +10 -name 'query-sydr*' -exec rm -rf {} \;"

## Alternative Fuzz Targets

PostgreSQL project has 2 fuzz targets.

### simple_query

    # sydr-fuzz -c simple_query.toml run -l debug --log-file sydr-fuzz.log

### json_parser

    # sydr-fuzz -c json_parser.toml run -l debug --log-file sydr-fuzz.log
