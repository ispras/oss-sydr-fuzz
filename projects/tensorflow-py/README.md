# TensorFlow-py

TensorFlow is an Open Source platform for machine learning. It has a comprehensive, flexible ecosystem of tools, libraries and community resources that lets researchers push the state-of-the-art in ML and developers easily build and deploy ML powered applications.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-tensorflow-py .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/tensorflow-py` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run -v /etc/localtime:/etc/localtime:ro --privileged --network host --rm -it -v $PWD:/fuzz oss-sydr-fuzz-tensorflow-py /bin/bash

Change the directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c abs.toml run

Minimize corpus:

    # sydr-fuzz -c abs.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c abs.toml pycov html

## Supported Targets

* abs
* acos 
* acosh
* add
* constant
* dataFormatVecPermute
* decode_png
* decode_wav
* encode_wav
* immutableConst
* raggedCountSparseOutput
* sparseCountSparseOutput
* string_decode_encode
* string_split_join
* string_upper_lower
* tf2migration
* load_model
* rgb_to_greyscale
* rgb_to_hsv
* stack_dynamic_partitions
* decode_image
