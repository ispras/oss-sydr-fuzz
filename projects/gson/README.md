# Gson 

Gson is a Java library that can be used to convert Java Objects into their JSON representation.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-gson .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/gson` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-gson /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run fuzzing:

    # sydr-fuzz -c FuzzReader.toml run

Minimize corpus:

    # sydr-fuzz -c FuzzReader.toml cmin 

Collect and report coverage:

    # sydr-fuzz -c FuzzReader.toml cov-html -s /java-diff-util/gson/src/main/java

## Alternative Fuzz Targets

Gson project has 3 fuzz targets.

### FuzzReader

    # sydr-fuzz -c FuzzReader.toml run

### FuzzParse

    # sydr-fuzz -c FuzzParse.toml run

### FuzzStreamParser

    # sydr-fuzz -c FuzzStreamParser.toml run
