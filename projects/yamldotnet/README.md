# YamlDotNet

YamlDotNet is a YAML library for netstandard and other .NET runtimes.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-yamldotnet .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/yamldotnet` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-yamldotnet /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run fuzzing with afl++:

    # sydr-fuzz -c parse_yaml.toml run

Minimize corpus:

    # sydr-fuzz -c parse_yaml.toml cmin

Collect coverage:

    # sydr-fuzz -c parse_yaml.toml cov-html
