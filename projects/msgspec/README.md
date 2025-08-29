# msgspec

A fast serialization and validation library, with builtin support for JSON, MessagePack, YAML, and TOML

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-msgspec .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/msgspec` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-msgspec /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

## Fuzz tagrets:

  * fuzz_json
  * fuzz_toml
  * fuzz_msgpack
  * fuzz_yaml-atheris
  * fuzz_yaml-pyafl

## Fuzzing

Run fuzzing:

    # sydr-fuzz -c yaml_fuzzer-atheris.toml run

Minimize corpus:

    # sydr-fuzz -c yaml_fuzzer-atheris.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c yaml_fuzzer-atheris.toml pycov html -- --source=msgspec,yaml,fuzz_yaml_atheris

Crash triage with Casr:

    # sydr-fuzz -c yaml_fuzzer-atheris.toml casr

