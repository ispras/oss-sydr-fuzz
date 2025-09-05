# Torchcodec

Torchcodec is an open source machine learning framework based on the Torch library, used for applications such as computer vision and natural language processing.

## Perfomance note

This project uses some performance related settings and you can tune this for your machine:

* `-rss_limit_mb=30720` in *.toml - Memory usage limit for libFuzzer (in Mb), default 30GB. Use 0 to disable the limit. If an input requires more than this amount of RSS memory to execute, the process is treated as a failure case. The limit is checked in a separate thread every second.

## Build Docker

    # sudo docker build -t oss-sydr-fuzz-torchcodec .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/torchcodec` directory:

    # unzip sydr.zip

Run Docker:

    # sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-torchcodec /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run libFuzzer-based hybrid fuzzing:

    # sydr-fuzz -c get_frames_audio-lf.toml run

Minimize corpus:

    # sydr-fuzz -c get_frames_audio-lf.toml cmin

Collect and report coverage:

    # sydr-fuzz -c get_frames_audio-lf.toml cov-html

Check security predicates:

    # sydr-fuzz -c get_frames_audio-lf.toml security

Crash analysis:

    # sydr-fuzz -c get_frames_audio-lf.toml casr

## Supported Targets

    * audio_encoder-lf
    * audio_encoder-afl++
    * file_frame_getter-lf
    * file_frame_getter-afl++
    * file_scan-lf
    * file_scan-afl++
    * get_frames_audio-lf
    * get_frames_audio-afl++

## Applied patches

* schema_type_parser-stoll.patch – Catch stull exceptions to allow the fuzzer go deeper.
