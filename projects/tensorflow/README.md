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

Minimize corpus:

    # sydr-fuzz -c cleanpath_fuzz.toml cmin

Collect and report coverage:

    # sydr-fuzz -c cleanpath_fuzz.toml cov-report

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c cleanpath_fuzz-afl++.toml run

## Check Security Predicates

Minimize corpus:

    # sydr-fuzz -c cleanpath_fuzz.toml cmin

Check security predicates on new corpus:

    # sydr-fuzz -c cleanpath_fuzz.toml security

## View coverage via browser

Run these commands to generate separate `html` files:

    # cd /fuzz
    # sydr-fuzz -c cleanpath_fuzz.toml cov-export -j 100 -- -format=lcov > cleanpath_fuzz.lcov
    # sed -i 's/:\/proc\/self\/cwd/:\/tensorflow/g' cleanpath_fuzz.lcov
    # sed -i "s/:\/tensorflow\/external/:$(find /root/.cache/bazel/_bazel_root -name 'com_google*' | grep external | grep -v execroot | head -1 | sed s'/external.*/external/g' | sed 's/\//\\\//g')/g" cleanpath_fuzz.lcov
    # genhtml -o /fuzz/cleanpath-cov-html/ cleanpath_fuzz.lcov

Open /fuzz/cleanpath-cov-html/index.html with browser.

## Alternative Fuzz Targets

TensorFlow project has 27 fuzz targets.

### arg_def_case_fuzz

    # sydr-fuzz -c arg_def_case_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c arg_def_case_fuzz.toml cov-report

### base64_fuzz

    # sydr-fuzz -c base64_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c base64_fuzz.toml cov-report

### check_numerics_fuzz

    # sydr-fuzz -c check_numerics_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c check_numerics_fuzz.toml cov-report

### cleanpath_fuzz

    # sydr-fuzz -c cleanpath_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c cleanpath_fuzz.toml cov-report

### consume_leading_digits_fuzz

    # sydr-fuzz -c consume_leading_digits_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c consume_leading_digits_fuzz.toml cov-report

### decode_bmp_fuzz

    # sydr-fuzz -c decode_bmp_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c decode_bmp_fuzz.toml cov-report

### decode_compressed_fuzz

    # sydr-fuzz -c decode_compressed_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c decode_compressed_fuzz.toml cov-report

### decode_csv_fuzz

    # sydr-fuzz -c decode_csv_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c decode_csv_fuzz.toml cov-report

### decode_json_example_fuzz

    # sydr-fuzz -c decode_json_example_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c decode_json_example_fuzz.toml cov-report

### decode_png_fuzz

    # sydr-fuzz -c decode_png_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c decode_png_fuzz.toml cov-report

### decode_wav_fuzz

    # sydr-fuzz -c decode_wav_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c decode_wav_fuzz.toml cov-report

### encode_base64_fuzz

    # sydr-fuzz -c encode_base64_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c encode_base64_fuzz.toml cov-report

### encode_jpeg_fuzz

    # sydr-fuzz -c encode_jpeg_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c encode_jpeg_fuzz.toml cov-report

### example_proto_fast_parsing_fuzz

    # sydr-fuzz -c example_proto_fast_parsing_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c example_proto_fast_parsing_fuzz.toml cov-report

### joinpath_fuzz

    # sydr-fuzz -c joinpath_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c joinpath_fuzz.toml cov-report

### one_hot_fuzz

    # sydr-fuzz -c one_hot_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c one_hot_fuzz.toml cov-report

### parseURI_fuzz

    # sydr-fuzz -c parseURI_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c parseURI_fuzz.toml cov-report

### parse_tensor_op_fuzz

    # sydr-fuzz -c parse_tensor_op_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c parse_tensor_op_fuzz.toml cov-report

### scatter_nd_fuzz

    # sydr-fuzz -c scatter_nd_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c scatter_nd_fuzz.toml cov-report

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

### string_split_fuzz

    # sydr-fuzz -c string_split_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c string_split_fuzz.toml cov-report

### string_split_v2_fuzz

    # sydr-fuzz -c string_split_v2_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c string_split_v2_fuzz.toml cov-report

### string_to_number_fuzz

    # sydr-fuzz -c string_to_number_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c string_to_number_fuzz.toml cov-report

### stringprintf_fuzz

    # sydr-fuzz -c stringprintf_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c stringprintf_fuzz.toml cov-report

### tstring_fuzz

    # sydr-fuzz -c tstring_fuzz.toml run

Collect and report coverage:

    # sydr-fuzz -c tstring_fuzz.toml cov-report
