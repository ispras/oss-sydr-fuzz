# cJSON

Ultralightweight JSON parser in ANSI C.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-cjson .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/cjson` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-cjson /bin/bash

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus /fuzz/corpus

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz run -l debug
