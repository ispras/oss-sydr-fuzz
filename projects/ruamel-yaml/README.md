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

  * yaml_fuzzer

## Fuzzing

### yaml

#### Run fuzzing:
##### Atheris

    # sydr-fuzz -c yaml_fuzzer_atheris.toml run

#### PythonAfl

    # sydr-fuzz -c yaml_fuzzer_pyafl.toml run

####Minimize corpus:
##### Atheirs
    
    # sydr-fuzz -c yaml_fuzzer_atheris.toml cmin

##### PythonAfl

    # sydr-fuzz -c yaml_fuzzer_pyafl.toml cmin

####Get HTML coverage report:
##### Atheris

    # sydr-fuzz -c yaml_fuzzer_atheris.toml pycov html -- --source=ruamel,yaml_fuzzer_atheris

##### PythonAfl

    # sydr-fuzz -c yaml_fuzzer_pyafl.toml pycov html -- --source=ruamel,yaml_fuzzer_pyafl


####Crash triage with Casr:
#### Atheris

    # sydr-fuzz -c yaml_fuzzer_atheris.toml casr -p

#### PythonAfl

    # sydr-fuzz -c yaml_fuzzer_pyafl.toml casr -p

