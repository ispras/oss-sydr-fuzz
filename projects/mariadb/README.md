# MariaDB

MariaDB was designed as a drop-in replacement of MySQL(R) with more features, new storage engines, fewer bugs, and better performance.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-mariadb .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/mariadb` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-mariadb /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c fuzz_json.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c fuzz_json-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c fuzz_json.toml cmin

Collect coverage:

    # sydr-fuzz -c fuzz_json.toml cov-export -- -format=lcov > fuzz_json.lcov
    # genhtml -o fuzz_json-html fuzz_json.lcov

Check security predicates:

    # sydr-fuzz -c fuzz_json.toml security
