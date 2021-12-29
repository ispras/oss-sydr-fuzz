# Open vSwitch

Open vSwitch is a multilayer software switch licensed under the open source
Apache 2 license.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-openvswitch .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/openvswitch` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-openvswitch /bin/bash

### Flow_extract fuzzing

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /openvswitch_fuzzers/corpus_flow_extract /fuzz/corpus_flow_extract

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c flow_extract.toml run

Collect coverage:

    # mkdir /fuzz/coverage_flow_extract && cd /fuzz/coverage_flow_extract
    # for filename in /fuzz/corpus_flow_extract/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /openvswitch_cov/flow_extract_target "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /openvswitch_cov/flow_extract_target -instr-profile=cov.profdata

### Json_parser fuzzing

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /openvswitch_fuzzers/corpus_json_parser /fuzz/corpus_json_parser

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c json_parser.toml run

Collect coverage:

    # mkdir /fuzz/coverage_json_parser && cd /fuzz/coverage_json_parser
    # for filename in /fuzz/corpus_json_parser/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /openvswitch_cov/json_parser_target "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /openvswitch_cov/json_parser_target -instr-profile=cov.profdata

### Ofp_print fuzzing

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /openvswitch_fuzzers/corpus_ofp_print /fuzz/corpus_ofp_print

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c ofp_print.toml run

Collect coverage:

    # mkdir /fuzz/coverage_ofp_print && cd /fuzz/coverage_ofp_print
    # for filename in /fuzz/corpus_ofp_print/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /openvswitch_cov/ofp_print_target "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /openvswitch_cov/ofp_print_target -instr-profile=cov.profdata

### Odp fuzzing

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c odp.toml run

Collect coverage:

    # mkdir /fuzz/coverage_odp && cd /fuzz/coverage_odp
    # for filename in /fuzz/corpus_odp/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /openvswitch_cov/odp_target "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /openvswitch_cov/odp_target -instr-profile=cov.profdata

### Ofctl_parse fuzzing

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c ofctl_parse.toml run

Collect coverage:

    # mkdir /fuzz/coverage_ofctl_parse && cd /fuzz/coverage_ofctl_parse
    # for filename in /fuzz/corpus_ofctl_parse/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /openvswitch_cov/ofctl_parse_target "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /openvswitch_cov/ofctl_parse_target -instr-profile=cov.profdata

### Miniflow fuzzing

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c miniflow.toml run

Collect coverage:

    # mkdir /fuzz/coverage_miniflow && cd /fuzz/coverage_miniflow
    # for filename in /fuzz/corpus_miniflow/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /openvswitch_cov/miniflow_target "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /openvswitch_cov/miniflow_target -instr-profile=cov.profdata
