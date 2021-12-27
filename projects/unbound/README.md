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

### Fuzz_1 fuzzing

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus_fuzz_1 /fuzz/corpus_fuzz_1

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_1.toml run

Collect coverage:

    # mkdir /fuzz/coverage_fuzz_1 && cd /fuzz/coverage_fuzz_1
    # for filename in /fuzz/corpus_fuzz_1/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /unbound_cov/fuzz_1_cov "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /unbound_cov/fuzz_1_cov -instr-profile=cov.profdata

### Fuzz_2 fuzzing

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus_fuzz_2 /fuzz/corpus_fuzz_2

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_2.toml run

Collect coverage:

    # mkdir /fuzz/coverage_fuzz_2 && cd /fuzz/coverage_fuzz_2
    # for filename in /fuzz/corpus_fuzz_2/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /unbound_cov/fuzz_2_cov "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /unbound_cov/fuzz_2_cov -instr-profile=cov.profdata

### Fuzz_3 fuzzing

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus_fuzz_3 /fuzz/corpus_fuzz_3

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_3.toml run

Collect coverage:

    # mkdir /fuzz/coverage_fuzz_3 && cd /fuzz/coverage_fuzz_3
    # for filename in /fuzz/corpus_fuzz_3/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /unbound_cov/fuzz_3_cov "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /unbound_cov/fuzz_3_cov -instr-profile=cov.profdata

### Fuzz_4 fuzzing

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus_fuzz_4 /fuzz/corpus_fuzz_4

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_4.toml run

Collect coverage:

    # mkdir /fuzz/coverage_fuzz_4 && cd /fuzz/coverage_fuzz_4
    # for filename in /fuzz/corpus_fuzz_4/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /unbound_cov/fuzz_4_cov "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /unbound_cov/fuzz_4_cov -instr-profile=cov.profdata

### Packet_fuzz fuzzing

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus_packet /fuzz/corpus_packet

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c packet.toml run

Collect coverage:

    # mkdir /fuzz/coverage_packet && cd /fuzz/coverage_packet
    # for filename in /fuzz/corpus_packet/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /unbound_cov/parse_packet_cov "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /unbound_cov/parse_packet_cov -instr-profile=cov.profdata
