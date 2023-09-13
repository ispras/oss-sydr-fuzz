# TensorFlow

TensorFlow is an Open Source platform for machine learning. It has a comprehensive, flexible ecosystem of tools, libraries and community resources that lets researchers push the state-of-the-art in ML and developers easily build and deploy ML powered applications.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-tensorflow .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/tensorflow` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run -v /etc/localtime:/etc/localtime:ro --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined --rm -it -v $PWD:/fuzz oss-sydr-fuzz-tensorflow /bin/bash

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
    # sed -i -e 's/\/proc\//\/cov\/proc\//g' cleanpath_fuzz.lcov
    # genhtml -o /fuzz/cleanpath-cov-html/ cleanpath_fuzz.lcov

Open /fuzz/cleanpath-cov-html/index.html with browser.

## Alternative Fuzz Targets

* AreAttrValuesEqual_fuzz
* BuildTensorAlwaysSucceedsWithValidTensorShape
* DebugStringCheck
* FuzzDecodeAndCropJpegArbitraryInput
* FuzzDecodeAndCropJpegValidInput
* FuzzDecodeBmpArbitraryInput
* FuzzDecodeBmpValidInput
* FuzzDecodeGifArbitraryInput
* FuzzDecodeImageArbitraryInput
* FuzzDecodeImageValidInput
* FuzzDecodeJpegArbitraryInput
* FuzzDecodeJpegValidInput
* FuzzDecodePngArbitraryInput
* FuzzDecodePngValidInput
* FuzzDecodeWavArbitraryInput
* FuzzDecodeWavValidInput
* FuzzFileRead
* FuzzGraphEndToEndAllStatic
* FuzzGraphEndToEndFDP
* FuzzGraphEndToEndSimpleFixedInput
* FuzzHLOParseUnverified
* FuzzImportGraphDef
* FuzzPartialTensorShape
* FuzzRemoveDimWithStatus
* FuzzSetDimWithStatus
* FuzzTensorShape
* ParseAttrValue_fuzz
* add_fuzz
* arg_def_case_fuzz
* base64_fuzz
* bfloat16_fuzz
* bincount_fuzz
* check_numerics_fuzz
* cleanpath_fuzz
* concat_fuzz
* consume_leading_digits_fuzz
* decode_bmp_fuzz
* decode_compressed_fuzz
* decode_csv_fuzz
* decode_json_example_fuzz
* decode_png_fuzz
* decode_wav_fuzz
* encode_base64_fuzz
* encode_jpeg_fuzz
* end_to_end_fuzz
* example_proto_fast_parsing_fuzz
* identity_fuzz
* joinpath_fuzz
* matmul_fuzz
* one_hot_fuzz
* parse_tensor_op_fuzz
* parseURI_fuzz
* saved_model
* scatter_nd_fuzz
* status_fuzz
* status_group_fuzz
* string_replace_fuzz
* string_to_number_fuzz
* stringprintf_fuzz
* tstring_fuzz
