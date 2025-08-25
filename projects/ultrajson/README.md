# ultrajson

UltraJSON is an ultra fast JSON encoder and decoder written in pure C with bindings for Python 3.7+.

## Build Docker
##### Atheris

    $ sudo docker build -t oss-sydr-fuzz-ultrajson-atheris --build-arg BUILD_SCRIPT=/build_atheris.sh .

##### PythonAfl

    $ sudo docker build -t oss-sydr-fuzz-ultrajson-pyafl --build-arg BUILD_SCRIPT=/build_pyafl.sh .

## Run Fuzzing

#### Unzip Sydr (`sydr.zip`) in `projects/ultrajson` directory:

    $ unzip sydr.zip

#### Run docker:
#### Atheris

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-ultrajson-atheris /bin/bash

#### PythonAfl

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-ultrajson-pyafl /bin/bash

#### Change directory to `/fuzz`:

    # cd /fuzz

## Fuzz tagrets:

  * hypothesis_structured_fuzzer
  * json_differential_fuzzer
  * ujson_fuzzer

## Fuzzing

### hypothesis_structured_fuzzer

#### Run fuzzing:

    # sydr-fuzz -c hypothesis_structured_fuzzer.toml run

#### Minimize corpus:

    # sydr-fuzz -c hypothesis_structured_fuzzer.toml cmin

#### Get HTML coverage report:

    # sydr-fuzz -c hypothesis_structured_fuzzer.toml pycov html

### json_differential_fuzzer

#### Run fuzzing:

    # sydr-fuzz -c json_differential_fuzzer.toml run

#### Minimize corpus:

    # sydr-fuzz -c json_differential_fuzzer.toml cmin

#### Get HTML coverage report:

    # sydr-fuzz -c json_differential_fuzzer.toml pycov html

### ujson_fuzzer

#### Run fuzzing:
##### Atheris

    # sydr-fuzz -c ujson_fuzzer_atheris.toml run

##### PythonAfl

    # sydr-fuzz -c ujson_fuzzer_pyafl.toml run

#### Minimize corpus:
##### Atheris

    # sydr-fuzz -c ujson_fuzzer_atheris.toml cmin

##### PythonAfl

    # sydr-fuzz -c ujson_fuzzer_pyafl.toml cmin

#### Get HTML coverage report:
##### Atheris

    # sydr-fuzz -c ujson_fuzzer_atheris.toml pycov html -- --source=ujson_fuzzer_atheris

##### PythonAfl

    # sydr-fuzz -c ujson_fuzzer_pyafl.toml pycov html -- --source=ujson_fuzzer_pyafl

