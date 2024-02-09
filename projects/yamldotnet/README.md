# YamlDotNet

YamlDotNet is a YAML library for netstandard and other .NET runtimes.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-yamldotnet .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/ffmpeg` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-yamldotnet /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run fuzzing with afl++:

    # sydr-fuzz run

Minimize corpus:

    # sydr-fuzz cmin

Collect coverage:

    # sydr-fuzz cov-html
