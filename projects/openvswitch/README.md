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

Change directory to `/fuzz`:

    # cd /fuzz

### Flow_extract fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c flow_extract.toml run

Collect coverage:

    # mkdir /fuzz/flow_extract-out/coverage && cd /fuzz/flow_extract-out/coverage
    # for filename in /fuzz/flow_extract-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /openvswitch_cov/flow_extract_target "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /openvswitch_cov/flow_extract_target -instr-profile=cov.profdata

### Json_parser fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c json_parser.toml run

Collect coverage:

    # mkdir /fuzz/json_parser-out/coverage && cd /fuzz/json_parser-out/coverage
    # for filename in /fuzz/json_parser-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /openvswitch_cov/json_parser_target "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /openvswitch_cov/json_parser_target -instr-profile=cov.profdata

### Ofp_print fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c ofp_print.toml run

Collect coverage:

    # mkdir /fuzz/ofp_print-out/coverage && cd /fuzz/ofp_print-out/coverage
    # for filename in /fuzz/ofp_print-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /openvswitch_cov/ofp_print_target "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /openvswitch_cov/ofp_print_target -instr-profile=cov.profdata

### Odp fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c odp.toml run

Collect coverage:

    # mkdir /fuzz/odp-out/coverage && cd /fuzz/odp-out/coverage
    # for filename in /fuzz/odp-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /openvswitch_cov/odp_target "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /openvswitch_cov/odp_target -instr-profile=cov.profdata

### Ofctl_parse fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c ofctl_parse.toml run

Collect coverage:

    # mkdir /fuzz/ofctl_parse-out/coverage && cd /fuzz/ofctl_parse-out/coverage
    # for filename in /fuzz/ofctl_parse-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /openvswitch_cov/ofctl_parse_target "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /openvswitch_cov/ofctl_parse_target -instr-profile=cov.profdata

### Miniflow fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c miniflow.toml run

Collect coverage:

    # mkdir /fuzz/miniflow-out/coverage && cd /fuzz/miniflow-out/coverage
    # for filename in /fuzz/miniflow-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /openvswitch_cov/miniflow_target "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /openvswitch_cov/miniflow_target -instr-profile=cov.profdata
