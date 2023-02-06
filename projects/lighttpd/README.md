# lighttpd

lighttpd a secure, fast, compliant and very flexible web-server
which has been optimized for high-performance environments. It has a very
low memory footprint compared to other webservers and takes care of cpu-load.
Its advanced feature-set (FastCGI, CGI, Auth, Output-Compression,
URL-Rewriting and many more) make lighttpd the perfect webserver-software
for every server that is suffering load problems.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-lighttpd .

## Run Hybrid Fuzzing

Run docker:

    $ sudo docker run --rm -v `pwd`:/fuzz -it oss-sydr-fuzz-lighttpd /bin/bash

Run hybrid fuzzing:

    # sydr-fuzz run

Minimize corpus:

    # sydr-fuzz -merge=1 /corpus_minimized /corpus

Collect coverage:

    # mkdir -p /coverage/raw && cd /coverage/raw
    # for file in /corpus_minimized/*; do LLVM_PROFILE_FILE=./$(basename "$file").profraw sydr-fuzz "$file"; done
    # cd .. && find raw/ > cov.lst
    # llvm-profdata merge --input-files=cov.lst -o cov.profdata

Get LCOV HTML coverage report:

    # sydr-fuzz cov-export -- -format=lcov > fuzz_burl.lcov
    # genhtml -o compress-html fuzz_burl.lcov