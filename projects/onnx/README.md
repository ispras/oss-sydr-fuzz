# ONNX

Open Neural Network Exchange (ONNX) provides an open AI standard for machine learning interoperability.

## Perfomance note

This project uses some performance related settings and you can tune this for your machine:

* `-rss_limit_mb=30720` in *.toml - Memory usage limit for libFuzzer (in Mb), default 30GB. Use 0 to disable the limit. If an input requires more than this amount of RSS memory to execute, the process is treated as a failure case. The limit is checked in a separate thread every second.

## Build Docker

    # sudo docker build -t oss-sydr-fuzz-onnx .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/onnx` directory:

    # unzip sydr.zip

Run Docker:

    # sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-onnx /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run libFuzzer-based hybrid fuzzing:

    # sydr-fuzz -c parse_model.toml run

Minimize corpus:

    # sydr-fuzz -c  parse_model.toml cmin

Collect coverage:

    # sydr-fuzz -c parse_model.toml cov-export -- -format=lcov > parse_model.lcov
    # genhtml -o parse_model_coverage parse_model.lcov

Check security predicates:

    # sydr-fuzz -c parse_model.toml security

Crash analysis:

    # sydr-fuzz -c parse_model.toml casr

To perform AFL-based hybrid fuzzing use *-afl++.toml configuration files:

    # sydr-fuzz -c parse_model-afl++.toml run

## Supported Targets

    * parse_model
    * parse_graph
    * check_model
