# PyTorch

PyTorch is an open source machine learning framework based on the Torch library, used for applications such as computer vision and natural language processing.

## Build Docker

    # sudo docker build -t oss-sydr-fuzz-pytorch-py .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/pytorch-py` directory:

    # unzip sydr.zip

Run Docker:

    # sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-pytorch-py /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c load_fuzz.toml run

Minimize corpus:

    # sydr-fuzz -c load_fuzz.toml cmin

Collect coverage:

    # sydr-fuzz -c load_fuzz.toml pycov html

## Supported Targets

    * load_fuzz
