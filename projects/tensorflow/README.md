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

Collect coverage:

    # mkdir /fuzz/cleanpath_fuzz-out/coverage && cd /fuzz/cleanpath_fuzz-out/coverage
    # for filename in /fuzz/cleanpath_fuzz-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /coverage/cleanpath_fuzz "$filename"; done
    # llvm-profdata merge *.profraw -o cov.profdata
    # llvm-cov report /coverage/cleanpath_fuzz -instr-profile=cov.profdata

## Alternative Fuzz Targets

TensorFlow project has 11 fuzz targets.

### arg_def_case_fuzz

    # sydr-fuzz -c arg_def_case_fuzz.toml run

Collect coverage:

    # mkdir /fuzz/arg_def_case_fuzz-out/coverage && cd /fuzz/arg_def_case_fuzz-out/coverage
    # for filename in /fuzz/arg_def_case_fuzz-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /coverage/arg_def_case_fuzz "$filename"; done
    # llvm-profdata merge *.profraw -o cov.profdata
    # llvm-cov report /coverage/arg_def_case_fuzz -instr-profile=cov.profdata

### base64_fuzz

    # sydr-fuzz -c base64_fuzz.toml run

Collect coverage:

    # mkdir /fuzz/base64_fuzz-out/coverage && cd /fuzz/base64_fuzz-out/coverage
    # for filename in /fuzz/base64_fuzz-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /coverage/base64_fuzz "$filename"; done
    # llvm-profdata merge *.profraw -o cov.profdata
    # llvm-cov report /coverage/base64_fuzz -instr-profile=cov.profdata

### cleanpath_fuzz

    # sydr-fuzz -c cleanpath_fuzz.toml run

Collect coverage:

    # mkdir /fuzz/cleanpath_fuzz-out/coverage && cd /fuzz/cleanpath_fuzz-out/coverage
    # for filename in /fuzz/cleanpath_fuzz-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /coverage/cleanpath_fuzz "$filename"; done
    # llvm-profdata merge *.profraw -o cov.profdata
    # llvm-cov report /coverage/cleanpath_fuzz -instr-profile=cov.profdata

### consume_leading_digits_fuzz

    # sydr-fuzz -c consume_leading_digits_fuzz.toml run

Collect coverage:

    # mkdir /fuzz/consume_leading_digits_fuzz-out/coverage && cd /fuzz/consume_leading_digits_fuzz-out/coverage
    # for filename in /fuzz/consume_leading_digits_fuzz-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /coverage/consume_leading_digits_fuzz "$filename"; done
    # llvm-profdata merge *.profraw -o cov.profdata
    # llvm-cov report /coverage/consume_leading_digits_fuzz -instr-profile=cov.profdata

### joinpath_fuzz

    # sydr-fuzz -c joinpath_fuzz.toml run

Collect coverage:

    # mkdir /fuzz/joinpath_fuzz-out/coverage && cd /fuzz/joinpath_fuzz-out/coverage
    # for filename in /fuzz/joinpath_fuzz-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /coverage/joinpath_fuzz "$filename"; done
    # llvm-profdata merge *.profraw -o cov.profdata
    # llvm-cov report /coverage/joinpath_fuzz -instr-profile=cov.profdata

### parseURI_fuzz

    # sydr-fuzz -c parseURI_fuzz.toml run

Collect coverage:

    # mkdir /fuzz/parseURI_fuzz-out/coverage && cd /fuzz/parseURI_fuzz-out/coverage
    # for filename in /fuzz/parseURI_fuzz-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /coverage/parseURI_fuzz "$filename"; done
    # llvm-profdata merge *.profraw -o cov.profdata
    # llvm-cov report /coverage/parseURI_fuzz -instr-profile=cov.profdata

### status_fuzz

    # sydr-fuzz -c status_fuzz.toml run

Collect coverage:

    # mkdir /fuzz/status_fuzz-out/coverage && cd /fuzz/status_fuzz-out/coverage
    # for filename in /fuzz/status_fuzz-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /coverage/status_fuzz "$filename"; done
    # llvm-profdata merge *.profraw -o cov.profdata
    # llvm-cov report /coverage/status_fuzz -instr-profile=cov.profdata

### status_group_fuzz

    # sydr-fuzz -c status_group_fuzz.toml run

Collect coverage:

    # mkdir /fuzz/status_group_fuzz-out/coverage && cd /fuzz/status_group_fuzz-out/coverage
    # for filename in /fuzz/status_group_fuzz-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /coverage/status_group_fuzz "$filename"; done
    # llvm-profdata merge *.profraw -o cov.profdata
    # llvm-cov report /coverage/status_group_fuzz -instr-profile=cov.profdata

### string_replace_fuzz

    # sydr-fuzz -c string_replace_fuzz.toml run

Collect coverage:

    # mkdir /fuzz/string_replace_fuzz-out/coverage && cd /fuzz/string_replace_fuzz-out/coverage
    # for filename in /fuzz/string_replace_fuzz-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /coverage/string_replace_fuzz "$filename"; done
    # llvm-profdata merge *.profraw -o cov.profdata
    # llvm-cov report /coverage/string_replace_fuzz -instr-profile=cov.profdata

### stringprintf_fuzz

    # sydr-fuzz -c stringprintf_fuzz.toml run

Collect coverage:

    # mkdir /fuzz/stringprintf_fuzz-out/coverage && cd /fuzz/stringprintf_fuzz-out/coverage
    # for filename in /fuzz/stringprintf_fuzz-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /coverage/stringprintf_fuzz "$filename"; done
    # llvm-profdata merge *.profraw -o cov.profdata
    # llvm-cov report /coverage/stringprintf_fuzz -instr-profile=cov.profdata

### tstring_fuzz

    # sydr-fuzz -c tstring_fuzz.toml run

Collect coverage:

    # mkdir /fuzz/tstring_fuzz-out/coverage && cd /fuzz/tstring_fuzz-out/coverage
    # for filename in /fuzz/tstring_fuzz-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /coverage/tstring_fuzz "$filename"; done
    # llvm-profdata merge *.profraw -o cov.profdata
    # llvm-cov report /coverage/tstring_fuzz -instr-profile=cov.profdata
