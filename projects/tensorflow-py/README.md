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

    # sydr-fuzz -c abs_fuzz.toml run

Minimize corpus:

    # sydr-fuzz -c abs_fuzz.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c abs_fuzz.toml pycov html

## Alternative Fuzz Targets

TensorFlow-py project has 10 fuzz targets.

### abs_fuzz

    # sydr-fuzz -c abs_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c abs_fuzz.toml pycov html

### acos_fuzz

    # sydr-fuzz -c acos_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c acos_fuzz.toml pycov html

### acosh_fuzz

    # sydr-fuzz -c acosh_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c acosh_fuzz.toml pycov html

### add_fuzz

    # sydr-fuzz -c add_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c add_fuzz.toml pycov html

### constant_fuzz

    # sydr-fuzz -c constant_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c constant_fuzz.toml pycov html

### dataFormatVecPermute_fuzz

    # sydr-fuzz -c dataFormatVecPermute_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c dataFormatVecPermute_fuzz.toml pycov html

### immutableConst_fuzz

    # sydr-fuzz -c immutableConst_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c immutableConst_fuzz.toml pycov html

### raggedCountSparseOutput_fuzz

    # sydr-fuzz -c raggedCountSparseOutput_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c raggedCountSparseOutput_fuzz.toml pycov html

### sparseCountSparseOutput_fuzz

    # sydr-fuzz -c sparseCountSparseOutput_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c sparseCountSparseOutput_fuzz.toml pycov html

### tf2migration_fuzz

    # sydr-fuzz -c tf2migration_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c tf2migration_fuzz.toml pycov html
