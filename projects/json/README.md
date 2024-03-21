# json 

C++ library for parsing and processing json files.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-json .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/json` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-json /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c parse_json.toml run

Minimize corpus:

    # sydr-fuzz -c parse_json.toml cmin

Check security predicates:

    # sydr-fuzz -c parse_json.toml security

Crash triage with CASR:

    # sydr-fuzz -c parse_json.toml casr

Get LCOV HTML coverage report:

    # sydr-fuzz -c parse_json.toml cov-html

## Alternative Fuzz Targets

json project has 6 fuzz targets.

### parse_bjdata

    # sydr-fuzz -c parse_bjdata.toml run

### parse_bson

    # sydr-fuzz -c parse_bson.toml run

### parse_cbor

    # sydr-fuzz -c parse_cbor.toml run

### parse_json

    # sydr-fuzz -c parse_json.toml run

### parse_msgpack

    # sydr-fuzz -c parse_msgpack.toml run

### parse_ubjson

    # sydr-fuzz -c parse_ubjson.toml run
