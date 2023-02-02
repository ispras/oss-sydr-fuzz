# PyTorch

PyTorch is an open source machine learning framework based on the Torch library, used for applications such as computer vision and natural language processing.

## Perfomance note

This project uses some performance related settings and you can tune this for your machine:

* `-rss_limit_mb=30720` in *.toml - Memory usage limit for libFuzzer (in Mb), default 30GB. Use 0 to disable the limit. If an input requires more than this amount of RSS memory to execute, the process is treated as a failure case. The limit is checked in a separate thread every second.

## Build Docker

    # sudo docker build -t oss-sydr-fuzz-pytorch .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/pytorch` directory:

    # unzip sydr.zip

Run Docker:

    # sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-pytorch /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run libFuzzer-based hybrid fuzzing:

    # sydr-fuzz -c load.toml run

Minimize corpus:

    # sydr-fuzz -c load.toml cmin

Collect coverage:

    # sydr-fuzz -c load.toml cov-export -- -format=lcov > load.lcov
    # genhtml -o load_coverage load.lcov

Check security predicates:

    # sydr-fuzz -c load.toml security

Crash analysis:

    # sydr-fuzz -c load.toml casr

To perform AFL-based hybrid fuzzing use *_afl.toml configuration files:

    # sydr-fuzz -c load_afl.toml run

### rpc_reproducer

These targets are used to double check the bugs found by rpc fuzzers (e.g. message_deserialize_fuzz).

There are 2 build:

1. Clean RPC reproducer without asan: `rpc_reproducer_nosan`
2. RPC reproducer with asan: `rpc_reproducer_asan`

## Supported Targets

    * class_parser
    * irparser
    * jit_differential
    * message_deserialize
    * load
    * mobile
    * dump

## Applied patches

* schema_type_parser-stoll.patch – Catch stull exceptions to allow the fuzzer go deeper.
