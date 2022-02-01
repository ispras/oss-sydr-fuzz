# Unbound

Unbound is a validating, recursive, caching DNS resolver. It is designed to be
fast and lean and incorporates modern features based on open standards.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-unbound .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/unbound` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-unbound /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### Fuzz_1 fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_1.toml run

Collect coverage:

    # mkdir /fuzz/fuzz_1-out/coverage && cd /fuzz/fuzz_1-out/coverage
    # for filename in /fuzz/fuzz_1-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /unbound_cov/fuzz_1_cov "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /unbound_cov/fuzz_1_cov -instr-profile=cov.profdata

### Fuzz_2 fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_2.toml run

Collect coverage:

    # mkdir /fuzz/fuzz_2-out/coverage && cd /fuzz/fuzz_2-out/coverage
    # for filename in /fuzz/fuzz_2-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /unbound_cov/fuzz_2_cov "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /unbound_cov/fuzz_2_cov -instr-profile=cov.profdata

### Fuzz_3 fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_3.toml run

Collect coverage:

    # mkdir /fuzz/fuzz_3-out/coverage && cd /fuzz/fuzz_3-out/coverage
    # for filename in /fuzz/fuzz_3-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /unbound_cov/fuzz_3_cov "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /unbound_cov/fuzz_3_cov -instr-profile=cov.profdata

### Fuzz_4 fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_4.toml run

Collect coverage:

    # mkdir /fuzz/fuzz_4-out/coverage && cd /fuzz/fuzz_4-out/coverage
    # for filename in /fuzz/fuzz_4-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /unbound_cov/fuzz_4_cov "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /unbound_cov/fuzz_4_cov -instr-profile=cov.profdata

### Packet_fuzz fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c packet.toml run

Collect coverage:

    # mkdir /fuzz/packet-out/coverage && cd /fuzz/packet-out/coverage
    # for filename in /fuzz/packet-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /unbound_cov/parse_packet_cov "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /unbound_cov/parse_packet_cov -instr-profile=cov.profdata
