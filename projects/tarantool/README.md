# Tarantool

Tarantool can be used in OLTP scenarios instead of relational databases, and
such a solution will work many times faster. With Tarantool, you can replace the
traditional bundle of database & cache and benefit from that by reducing
operational costs.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-tarantool .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/tarantool` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-tarantool /bin/bash

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus_uri /fuzz/corpus_uri

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c uri.toml run -l debug

## Alternative Fuzz Targets

Tarantool project has 5 fuzz targets.

### csv

    # cp -r /corpus_csv /fuzz/corpus_csv
    # cd /fuzz
    # sydr-fuzz -c csv.toml run -l debug

### http_parser

    # cp -r /corpus_http_parser /fuzz/corpus_http_parser
    # cd /fuzz
    # sydr-fuzz -c http_parser.toml run -l debug

### uri

    # cp -r /corpus_uri /fuzz/corpus_uri
    # cd /fuzz
    # sydr-fuzz -c uri.toml run -l debug

### swim_proto_member

    # cd /fuzz
    # sydr-fuzz -c swim_proto_member.toml run -l debug

### swim_proto_meta

    # cd /fuzz
    # sydr-fuzz -c swim_proto_meta.toml run -l debug
