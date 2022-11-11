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

    # sydr-fuzz -c v8_compile-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c v8_compile-afl++.toml cmin

Collect coverage:

    # sydr-fuzz -c v8_compile-afl++.toml cov-export -- -format=lcov > nodejs.lcov
    # genhtml -o nodejs nodejs.lcov

Check security predicates:

    # sydr-fuzz -c v8_compile-afl++.toml security

## Alternative Fuzz Targets

Nodejs projects has 2 alternative fuzz targets.

### fuzz\_env

    # sydr-fuzz -c env.toml run

### fuzz\_url

    # sydr-fuzz -c url.toml run

or

    # sydr-fuzz -c url-afl++.toml run
