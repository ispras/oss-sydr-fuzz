# behaviortreecpp

behaviortreecpp is a C++ library for creating, executing, and testing behavior trees.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-behaviortreecpp .

## Run Hybrid Fuzzing with libfuzzer

Unzip Sydr (`sydr.zip`) in `projects/behaviortreecpp` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-behaviortreecpp /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c tomls/bt-lf.toml run

Minimize corpus:

    # sydr-fuzz -c tomls/bt-lf.toml cmin

Check security predicates:

    # sydr-fuzz -c tomls/bt-lf.toml security

Crash triage with CASR:

    # sydr-fuzz -c tomls/bt-lf.toml casr

Get LCOV HTML coverage report:

    # sydr-fuzz -c tomls/bt-lf.toml cov-export -- -format=lcov > bt.lcov
    # genhtml -o bt-html bt.lcov

## Run Hybrid Fuzzing with afl++:

To use afl++ in libfuzzer, you need to extract the file in the same way, run docker, and change the directory.

Run hybrid fuzzing:

    # sydr-fuzz -c tomls/bt-afl++.toml run

## Alternative Fuzz Targets

behaviortreecpp project has 3 fuzz targets.

### libfuzzer

    # sydr-fuzz -c tomls/bb-lf.toml     run
    # sydr-fuzz -c tomls/bt-lf.toml     run
    # sydr-fuzz -c tomls/script-lf.toml run
    
### afl++

    # sydr-fuzz -c tomls/bb-afl++.toml     run
    # sydr-fuzz -c tomls/bt-afl++.toml     run
    # sydr-fuzz -c tomls/script-afl++.toml run
