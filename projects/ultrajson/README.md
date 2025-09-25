# ultrajson

UltraJSON is an ultra fast JSON encoder and decoder written in pure C with bindings for Python 3.7+.

## Build Docker
##### Atheris

    $ sudo docker build -t oss-sydr-fuzz-ultrajson-atheris --build-arg BUILD_SCRIPT=/build_atheris.sh .

##### PythonAfl

    $ sudo docker build -t oss-sydr-fuzz-ultrajson-pyafl --build-arg BUILD_SCRIPT=/build_pyafl.sh .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/ultrajson` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-ultrajson-atheris /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

## Fuzz tagrets:

  * hypothesis_structured_fuzzer
  * json_differential_fuzzer
  * ujson_fuzzer-atheris
  * ujson_fuzzer-pyafl

## Fuzzing

Run fuzzing:

    # sydr-fuzz -c ujson_fuzzer-atheris.toml run

Minimize corpus:

    # sydr-fuzz -c ujson_fuzzer-atheris.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c ujson_fuzzer-atheris.toml pycov html -- --source=ujson_fuzzer_atheris

Crash triage with Casr:

    # sydr-fuzz -c ujson_fuzzer-atheris.toml casr

