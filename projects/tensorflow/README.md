# TensorFlow

TensorFlow is an Open Source platform for machine learning. It has a comprehensive, flexible ecosystem of tools, libraries and community resources that lets researchers push the state-of-the-art in ML and developers easily build and deploy ML powered applications.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-tensorflow .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/tensorflow` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run -v /etc/localtime:/etc/localtime:ro --privileged --network host --rm -it -v $PWD:/fuzz oss-sydr-fuzz-tensorflow /bin/bash

Change the directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c cleanpath_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c cleanpath_fuzz.toml cov-report

## Alternative Fuzz Targets

TensorFlow project has 11 fuzz targets.

### arg_def_case_fuzz

    # sydr-fuzz -c arg_def_case_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c arg_def_case_fuzz.toml cov-report

### base64_fuzz

    # sydr-fuzz -c base64_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c base64_fuzz.toml cov-report

### cleanpath_fuzz

    # sydr-fuzz -c cleanpath_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c cleanpath_fuzz.toml cov-report

### consume_leading_digits_fuzz

    # sydr-fuzz -c consume_leading_digits_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c consume_leading_digits_fuzz.toml cov-report

### joinpath_fuzz

    # sydr-fuzz -c joinpath_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c joinpath_fuzz.toml cov-report

### parseURI_fuzz

    # sydr-fuzz -c parseURI_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c parseURI_fuzz.toml cov-report

### status_fuzz

    # sydr-fuzz -c status_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c status_fuzz.toml cov-report

### status_group_fuzz

    # sydr-fuzz -c status_group_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c status_group_fuzz.toml cov-report

### string_replace_fuzz

    # sydr-fuzz -c string_replace_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c string_replace_fuzz.toml cov-report

### stringprintf_fuzz

    # sydr-fuzz -c stringprintf_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c stringprintf_fuzz.toml cov-report

### tstring_fuzz

    # sydr-fuzz -c tstring_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c tstring_fuzz.toml cov-report
