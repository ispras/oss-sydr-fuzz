# Capstone Engine

Capstone is a disassembly framework with the target of becoming the ultimate
disasm engine for binary analysis and reversing in the security community.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-capstone .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/capstone` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-capstone /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run
