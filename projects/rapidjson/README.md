# RapidJSON

A fast JSON parser/generator for C++ with both SAX/DOM style API

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-rapidjson .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/rapidjson` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host --rm -it -v $PWD:/fuzz oss-sydr-fuzz-rapidjson /bin/bash

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus /fuzz/corpus

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run -l debug -s file-info
