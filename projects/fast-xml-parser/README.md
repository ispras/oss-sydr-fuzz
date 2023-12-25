# fast-xml-parser

Javascript project to Validate XML, Parse XML and Build XML rapidly without C/C++ based libraries and no callback.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-fastxmlparser .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/fast-xml-parser` directory:

    $ unzip sydr.zip

Run docker (mount project directory to /jazzer.js subdirectory):

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/jazzer.js/fuzz oss-sydr-fuzz-fastxmlparser /bin/bash

Change directory to `/jazzer.js/fuzz`:

    # cd /jazzer.js/fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c xml.toml run

Minimize corpus:

    # sydr-fuzz -c xml.toml cmin

Collect and report coverage:

    # sydr-fuzz -c xml.toml cov-html

Analyze found bugs:

    # sydr-fuzz -c xml.toml casr

