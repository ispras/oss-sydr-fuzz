# brotli

Brotli is a generic-purpose lossless compression algorithm that compresses data
using a combination of a modern variant of the LZ77 algorithm, Huffman coding
and 2nd order context modeling. It is developed by Google and is widely used
for HTTP compression.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-brotli .

## Run Docker

    $ sudo docker run --rm -it -v $PWD:/fuzz oss-sydr-fuzz-brotli /bin/bash

## Run Fuzzing

Run libFuzzer:

    # /decode_fuzzer_libfuzzer -close_fd_mask=3 /corpus

Wait for INITED line, then stop with Ctrl+C.

## Collect Coverage

    # mkdir -p /coverage/raw && cd /coverage/raw
    # for file in /corpus/*; do LLVM_PROFILE_FILE=./$(basename "$file").profraw /decode_fuzzer_coverage "$file"; done
    # cd .. && find raw/ > cov.lst
    # llvm-profdata merge --input-files=cov.lst -o cov.profdata
    # llvm-cov export /decode_fuzzer_coverage -instr-profile cov.profdata -format=lcov > cov.lcov
    # genhtml -o cov-html cov.lcov
    # cp -r cov-html /fuzz/

Open `cov-html/index.html` in browser on host.

## Run Hybrid Fuzzing (requires sydr-fuzz)

Run docker with Sydr support:

    $ sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-brotli /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libFuzzer:

    # sydr-fuzz -c decode-lf.toml run

Run hybrid fuzzing with AFL++:

    # sydr-fuzz -c decode-afl.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz -c decode-lf.toml cov-export -- -format=lcov > decode.lcov
    # genhtml -o decode-html decode.lcov