# gdb-command

gdb-command is a library providing API for manipulating gdb in batch mode. It
supports:

* Execution of target program (Local type).
* Opening core of target program (Core type).
* Attaching to remote process (Remote type).

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-gdb-command .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/gdb-command` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-gdb-command /bin/bash

### Run Fuzzing

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c from_gdb.toml run

Collect coverage:

    # sydr-fuzz -c from_gdb.toml cov-export -- -format=lcov > from_gdb.lcov
    # genhtml --ignore-errors source -o from_gdb_html from_gdb.lcov
