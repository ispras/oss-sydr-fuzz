# PyTorch

PyTorch is an open source machine learning framework based on the Torch library, used for applications such as computer vision and natural language processing.

## Perfomance note

This project uses some performance related settings and you can tune this for your machine:

* `-rss_limit_mb=30720` in *.toml - Memory usage limit for libFuzzer (in Mb), default 30GB. Use 0 to disable the limit. If an input requires more than this amount of RSS memory to execute, the process is treated as a failure case. The limit is checked in a separate thread every second.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-pytorch .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/pytorch` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-pytorch /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### Fuzz Targets

#### dump_fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c dump.toml run

Minimize corpus:

    # sydr-fuzz -c dump.toml cmin

#### load_fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c load.toml run

Minimize corpus:

    # sydr-fuzz -c load.toml cmin

#### mobile_fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c mobile.toml run

Minimize corpus:

    # sydr-fuzz -c mobile.toml cmin

## Security predicates

    # sydr-fuzz -c <target_name>.toml security

## Crash analysis with Casr

    # sydr-fuzz -c <target_name>.toml casr

## Applied patches

* miniz.* – Updated miniz version to fix segmentation fault.
* stoull.patch – Catch stoull exception to allow the fuzzer go deeper.
