# node-xml2js

node-xml2js is a simple XML to JavaScript object converter that supports bi-directional conversion.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-nodexml2js .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/node-xml2js` directory:

    $ unzip sydr.zip

Run docker (mount project directory to /jazzer.js subdirectory):

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/jazzer.js/fuzz oss-sydr-fuzz-nodexml2js /bin/bash

Change directory to `/jazzer.js/fuzz`:

    # cd /jazzer.js/fuzz

Run fuzzing:

    # sydr-fuzz -c xml2js.toml run

Minimize corpus:

    # sydr-fuzz -c xml2js.toml cmin

Collect and report coverage:

    # sydr-fuzz -c xml2js.toml cov-html

Analyze found bugs:

    # sydr-fuzz -c xml2js.toml casr
