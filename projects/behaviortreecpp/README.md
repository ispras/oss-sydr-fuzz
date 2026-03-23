# BehaviorTree.CPP

BehaviorTree.CPP is a C++ library for creating, executing, and testing behavior trees.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-behaviortreecpp .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/behaviortreecpp` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-behaviortreecpp /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c bt-lf.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz -c bt-lf.toml cov-export -- -format=lcov > bt.lcov
    # genhtml -o bt-html bt.lcov

## Alternative Fuzz Targets

BehaviorTree.CPP project has 3 fuzz targets.

### bt

    # sydr-fuzz -c bt-lf.toml run

### script

    # sydr-fuzz -c script-lf.toml run

### bb

    # sydr-fuzz -c bb-lf.toml run
