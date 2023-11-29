# TinyGLTF

TinyGLTF is a header only C++11 glTF 2.0 library.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-tinygltf .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/tinygltf` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-tinygltf /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c loader_example.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c loader_example-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c loader_example.toml cmin

Collect coverage:

    # sydr-fuzz -c loader_example.toml cov-export -- -format=lcov > loader_example.lcov
    # genhtml -o loader_example-html loader_example.lcov

Check security predicates:

    # sydr-fuzz -c loader_example.toml security

Supported fuzz targets:

    # loader_example
    # fuzz_gltf
