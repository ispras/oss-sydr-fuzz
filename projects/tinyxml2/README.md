# TinyXML2

TinyXML2 is a simple, small, efficient, C++ XML parser that can be easily
integrated into other programs.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-tinyxml2 .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/tinyxml2` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-tinyxml2 /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run

Minimize corpus:

    # sydr-fuzz cmin

Collect coverage:

    # sydr-fuzz cov-export -- -format=lcov > tinyxml2.lcov
    # genhtml -o tinyxml2-html tinyxml2.lcov

Check security predicates:

    # sydr-fuzz security
