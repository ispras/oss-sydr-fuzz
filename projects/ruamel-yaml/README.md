# ruamel.yaml

ruamel.yaml is a YAML 1.2 loader/dumper package for Python

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-ruamel-yaml .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/pillow` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-ruamel-yaml /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

## Fuzz tagrets:

  * yaml_fuzzer

## Fuzzing

### pillow

Run fuzzing:

    # sydr-fuzz -c yaml_fuzzer.toml run

Minimize corpus:

    # sydr-fuzz -c yaml_fuzzer.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c yaml_fuzzer.toml pycov html

