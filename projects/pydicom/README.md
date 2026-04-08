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

  * dcmread_fuzzer

## Fuzzing

Run fuzzing:

    # sydr-fuzz -c dcmread-pyafl.toml run

Minimize corpus:

    # sydr-fuzz -c dcmread-pyafl.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c dcmread-pyafl.toml pycov html -- --source=pydicom,dcmread_fuzzer

Crash triage with Casr:

    # sydr-fuzz -c dcmread-pyafl.toml casr

