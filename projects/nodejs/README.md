# Nodejs

Node.js is an open-source, cross-platform JavaScript runtime environment.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-nodejs .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/nodejs` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-nodejs /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -C sydr_fuzz_afl++.toml run 

Minimize corpus:

    # sydr-fuzz -C sydr_fuzz_afl++.toml cmin

Collect coverage:

    # sydr-fuzz cov-export -- -format=lcov > nodejs.lcov
    # genhtml -o nodejs nodejs.lcov

Check security predicates:

    # sydr-fuzz security
