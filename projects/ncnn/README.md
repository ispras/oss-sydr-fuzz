# ncnn

ncnn is a high-performance neural network inference framework optimized for the mobile platform

## Build Docker

    # sudo docker build -t oss-sydr-fuzz-ncnn .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/onnx` directory:

    # unzip sydr.zip

Run Docker:

    # sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-ncnn /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run libFuzzer-based hybrid fuzzing:

    # sydr-fuzz -c ncnn_imread-lf.toml run

Minimize corpus:

    # sydr-fuzz -c ncnn_imread-lf.toml cmin

Collect coverage:

    # sydr-fuzz -c ncnn_imread-lf.toml cov-html

Check security predicates:

    # sydr-fuzz -c ncnn_imread-lf.toml security

Crash analysis:

    # sydr-fuzz -c ncnn_imread-lf.toml casr

To perform AFL-based hybrid fuzzing use *-afl++.toml configuration files:

    # sydr-fuzz -c ncnn_imread-afl++.toml run

## Supported Targets

    * darknet_cfg
    * ncnn_imread
    * mxnet_json_read
