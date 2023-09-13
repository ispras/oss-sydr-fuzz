# goblin

libgoblin aims to be your one-stop shop for binary parsing, loading, and
analysis.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-goblin .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/goblin` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-goblin /bin/bash

### Run Fuzzing

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c parse.toml run

Collect coverage:

    # sydr-fuzz -c parse.toml cov-export -- -format=lcov > parse.lcov
    # genhtml --ignore-errors source -o parse_html parse.lcov


## Alternative Fuzz Targets

goblin project has 2 fuzz targets.

### parse

    # cd /fuzz
    # sydr-fuzz -c parse.toml run

### parse_elf

    # cd /fuzz
    # sydr-fuzz -c parse_elf.toml run
