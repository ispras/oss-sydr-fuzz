# libjpeg

Libjpeg is a widely used C library for reading and writing JPEG image files. 
It was developed by Tom Lane and the Independent JPEG Group (IJG) during the 1990's 
and it is now maintained by several developers using various services 
identified in the SourceForge summary. 

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libjpeg .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libjpeg-turbo` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libjpeg /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c compress.toml run

