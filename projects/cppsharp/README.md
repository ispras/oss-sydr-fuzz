# CppSharp

CppSharp is a tool and set of libraries which facilitates the usage of native C/C++ code with the .NET ecosystem.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-cppsharp .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/cppsharp` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-cppsharp /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run fuzzing with afl++:

    # sydr-fuzz -c parse_cpp.toml run

Minimize corpus:

    # sydr-fuzz -c parse_cpp.toml cmin

Collect coverage:

    # sydr-fuzz -c parse_cpp.toml cov-html

Crash triage with Casr:

    # sydr-fuzz -c parse_cpp.toml casr
