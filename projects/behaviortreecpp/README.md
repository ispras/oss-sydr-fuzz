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

    # sydr-fuzz -c tomls/bt_fuzz.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz -c tomls/bt_fuzz.toml cov-export -- -format=lcov > bt.lcov
    # genhtml -o bt-html bt.lcov

## Alternative Fuzz Targets

BehaviorTree.CPP project has 3 fuzz targets.

### bb

    # sydr-fuzz -c tomls/bb_fuzz.toml run
    
### bt

    # sydr-fuzz -c tomls/bt_fuzz.toml run

### script

    # sydr-fuzz -c tomls/script_fuzz.toml run
