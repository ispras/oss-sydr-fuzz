# lighttpd

lighttpd is a secure, fast, compliant and very flexible web-server
which has been optimized for high-performance environments. It has a very
low memory footprint compared to other webservers and takes care of cpu-load.
Its advanced feature-set (FastCGI, CGI, Auth, Output-Compression,
URL-Rewriting and many more) make lighttpd the perfect webserver-software
for every server that is suffering load problems.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-lighttpd .

## Run Hybrid Fuzzing

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-lighttpd /bin/bash

Change directory to /fuzz:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run

Minimize corpus:

    # sydr-fuzz cmin

Collect coverage:

    # sydr-fuzz cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz cov-export -- -format=lcov > fuzz_burl.lcov
    # genhtml -o compress-html fuzz_burl.lcov
