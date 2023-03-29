# msgspec

A fast serialization and validation library, with builtin support for JSON, MessagePack, YAML, and TOML

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-msgspec .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/msgspec` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-msgspec /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

## Fuzz tagrets:

  * fuzz_json
  * fuzz_toml
  * fuzz_yaml
  * fuzz_msgpack

## Fuzzing

### yaml

Run fuzzing:

    # sydr-fuzz -c json_fuzzer.toml run

Minimize corpus:

    # sydr-fuzz -c json_fuzzer.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c json_fuzzer.toml pycov html

