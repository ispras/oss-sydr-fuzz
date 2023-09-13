# Torchaudio

This library is part of the PyTorch project. PyTorch is an open source machine learning framework.
The aim of torchaudio is to apply PyTorch to the audio domain.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-torchaudio .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/torchaudio` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-torchaudio /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c load_audio.toml run

Minimize corpus:

    # sydr-fuzz -c load_audio.toml cmin

Collect and report coverage:

    # sydr-fuzz -c load_audio.toml cov-report

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c load_audio-afl++.toml run
