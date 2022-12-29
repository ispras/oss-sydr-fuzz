# ultrajson

UltraJSON is an ultra fast JSON encoder and decoder written in pure C with bindings for Python 3.7+.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-ultrajson .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/ultrajson` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-ultrajson /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

## Fuzz tagrets:

  * hypothesis_structured_fuzzer
  * json_differential_fuzzer
  * ujson_fuzzer

## Fuzzing

### hypothesis_structured_fuzzer

Run fuzzing:

    # sydr-fuzz -c hypothesis_structured_fuzzer.toml run

Minimize corpus:

    # sydr-fuzz -c hypothesis_structured_fuzzer.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c hypothesis_structured_fuzzer.toml pycov html

### json_differential_fuzzer

Run fuzzing:

    # sydr-fuzz -c json_differential_fuzzer.toml run

Minimize corpus:

    # sydr-fuzz -c json_differential_fuzzer.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c json_differential_fuzzer.toml pycov html

### ujson_fuzzer

Run fuzzing:

    # sydr-fuzz -c ujson_fuzzer.toml run

Minimize corpus:

    # sydr-fuzz -c ujson_fuzzer.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c ujson_fuzzer.toml pycov html
