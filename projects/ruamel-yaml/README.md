# ruamel.yaml

ruamel.yaml is a YAML 1.2 loader/dumper package for Python

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-ruamel-yaml .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/ruamel-yaml` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-ruamel-yaml /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

## Fuzz tagrets:

  * yaml_fuzzer-atheris
  * yaml_fuzzer-pyafl

## Fuzzing

Run fuzzing:

    # sydr-fuzz -c yaml_fuzzer-atheris.toml run

Minimize corpus:
    
    # sydr-fuzz -c yaml_fuzzer-atheris.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c yaml_fuzzer-atheris.toml pycov html -- --source=ruamel,yaml_fuzzer_atheris

Crash triage with Casr:

    # sydr-fuzz -c yaml_fuzzer-atheris.toml casr

