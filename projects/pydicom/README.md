# pydicom

A DICOM file reading and writing library, with builtin support for parsing medical imaging metadata, pixel data, and nested datasets

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-pydicom .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/pydicom` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-pydicom /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

## Fuzz tagrets:

  * fuzz_pyafl

## Fuzzing

Run fuzzing:

    # sydr-fuzz -c fuzzer-pyafl.toml run

Minimize corpus:

    # sydr-fuzz -c fuzzer-pyafl.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c fuzzer-pyafl.toml pycov html -- --source=pydicom,fuzz_pyafl

Crash triage with Casr:

    # sydr-fuzz -c fuzzer-pyafl.toml casr

