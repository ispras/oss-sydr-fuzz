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

## Alternative Fuzz Targets

TensorFlow-py project has 10 fuzz targets.

### abs

    # sydr-fuzz -c abs.toml run

Collect and report coverage:

    # sydr-fuzz -c abs.toml pycov html

### acos

    # sydr-fuzz -c acos.toml run

Collect and report coverage:

    # sydr-fuzz -c acos.toml pycov html

### acosh

    # sydr-fuzz -c acosh.toml run

Collect and report coverage:

    # sydr-fuzz -c acosh.toml pycov html

### add

    # sydr-fuzz -c add.toml run

Collect and report coverage:

    # sydr-fuzz -c add.toml pycov html

### constant

    # sydr-fuzz -c constant.toml run

Collect and report coverage:

    # sydr-fuzz -c constant.toml pycov html

### dataFormatVecPermute

    # sydr-fuzz -c dataFormatVecPermute.toml run

Collect and report coverage:

    # sydr-fuzz -c dataFormatVecPermute.toml pycov html

### immutableConst

    # sydr-fuzz -c immutableConst.toml run

Collect and report coverage:

    # sydr-fuzz -c immutableConst.toml pycov html

### raggedCountSparseOutput

    # sydr-fuzz -c raggedCountSparseOutput.toml run

Collect and report coverage:

    # sydr-fuzz -c raggedCountSparseOutput.toml pycov html

### sparseCountSparseOutput

    # sydr-fuzz -c sparseCountSparseOutput.toml run

Collect and report coverage:

    # sydr-fuzz -c sparseCountSparseOutput.toml pycov html

### tf2migration

    # sydr-fuzz -c tf2migration.toml run

Collect and report coverage:

    # sydr-fuzz -c tf2migration.toml pycov html
