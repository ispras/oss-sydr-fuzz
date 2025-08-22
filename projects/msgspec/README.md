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
  * fuzz_yaml
  * fuzz_msgpack

## Fuzzing

### yaml

#### Run fuzzing:
##### Atheris

    # sydr-fuzz -c yaml_fuzzer_atheris.toml run

##### PythonAfl

    # sydr-fuzz -c yaml_fuzzer_pyafl.toml run

#### Minimize corpus:
##### Atheris

    # sydr-fuzz -c yaml_fuzzer_atheris.toml cmin

##### PythonAfl

    # sydr-fuzz -c yaml_fuzzer_pyafl.toml cmin

#### Get HTML coverage report:
##### Atheris

    # sydr-fuzz -c yaml_fuzzer_atheris.toml pycov html -- --source=msgspec,yaml,fuzz_yaml_atheris

##### PythonAfl

    # sydr-fuzz -c yaml_fuzzer_pyafl.toml pycov html -- --source=msgspec,yaml,fuzz_yaml_pyafl
