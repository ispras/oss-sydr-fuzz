
# vulkan-loader

vulkan-loader is a project for fuzzing Vulkan Loader in OSS-Sydr-Fuzz.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-vulkan-loader .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/vulkan-loader` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-vulkan-loader /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c tomls/instance-create-lf.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c tomls/instance-create-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c tomls/instance-create-lf.toml cmin

Check security predicates:

    # sydr-fuzz -c tomls/instance-create-lf.toml security

Crash triage with CASR:

    # sydr-fuzz -c tomls/instance-create-lf.toml casr

Get LCOV HTML coverage report:

    # sydr-fuzz -c tomls/instance-create-lf.toml cov-export -- -format=lcov > instance-create.lcov
    # genhtml -o instance-create-html instance-create.lcov

## Alternative Fuzz Targets

vulkan-loader project has 6 fuzz targets.

### libfuzzer

    # sydr-fuzz -c tomls/instance-create-advanced-lf.toml       run
    # sydr-fuzz -c tomls/instance-create-lf.toml                run
    # sydr-fuzz -c tomls/instance-enumerate-lf.toml             run
    # sydr-fuzz -c tomls/instance-enumerate-split-input-lf.toml run
    # sydr-fuzz -c tomls/json-load-lf.toml                      run
    # sydr-fuzz -c tomls/settings-lf.toml                       run

### afl++

    # sydr-fuzz -c tomls/instance-create-advanced-afl++.toml       run
    # sydr-fuzz -c tomls/instance-create-afl++.toml                run
    # sydr-fuzz -c tomls/instance-enumerate-afl++.toml             run
    # sydr-fuzz -c tomls/instance-enumerate-split-input-afl++.toml run
    # sydr-fuzz -c tomls/json-load-afl++.toml                      run
    # sydr-fuzz -c tomls/settings-afl++.toml                       run
