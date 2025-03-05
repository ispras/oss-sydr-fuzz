# xml2lua

xml2lua is an XML parser written entirely in Lua.

## Build docker

    $ sudo docker build -t oss-sydr-fuzz-xml2lua .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/xml2lua` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-xml2lua /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run fuzzing:

    # sydr-fuzz -c parse_xml.toml run

Get LuaCov coverage report:

    # sydr-fuzz -c parse_xml.toml luacov

Get LuaCov HTML coverage report:

    # sydr-fuzz -c parse_xml.toml cov-html
