# lighttpd

lighttpd is a secure, fast, compliant and very flexible web-server
which has been optimized for high-performance environments.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-lighttpd .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/lighttpd` directory:

    $ unzip sydr.zip

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
