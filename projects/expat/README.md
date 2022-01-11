# Expat

This is Expat, a C library for parsing XML, started by James Clark in 1997.
Expat is a stream-oriented XML parser. This means that you register handlers
with the parser before starting the parse. These handlers are called when the
parser discovers the associated structures in the document being parsed. A start
tag is an example of the kind of structures for which you may register handlers.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-expat .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/expat` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-expat /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c xml_parse_fuzzer_UTF-8.toml run

## Alternative Fuzz Targets

Expat project has 12 fuzz targets.

### xml_parsebuffer_fuzzer_ISO-8859-1

    # sydr-fuzz -c xml_parsebuffer_fuzzer_ISO-8859-1.toml run

### xml_parsebuffer_fuzzer_US-ASCII

    # sydr-fuzz -c xml_parsebuffer_fuzzer_US-ASCII.toml run

### xml_parsebuffer_fuzzer_UTF-16BE

    # sydr-fuzz -c xml_parsebuffer_fuzzer_UTF-16BE.toml run

### xml_parsebuffer_fuzzer_UTF-16LE

    # sydr-fuzz -c xml_parsebuffer_fuzzer_UTF-16LE.toml run

### xml_parsebuffer_fuzzer_UTF-16

    # sydr-fuzz -c xml_parsebuffer_fuzzer_UTF-16.toml run

### xml_parsebuffer_fuzzer_UTF-8

    # sydr-fuzz -c xml_parsebuffer_fuzzer_UTF-8.toml run

### xml_parse_fuzzer_ISO-8859-1

    # sydr-fuzz -c xml_parse_fuzzer_ISO-8859-1.toml run

### xml_parse_fuzzer_US-ASCII

    # sydr-fuzz -c xml_parse_fuzzer_US-ASCII.toml run

### xml_parse_fuzzer_UTF-16BE

    # sydr-fuzz -c xml_parse_fuzzer_UTF-16BE.toml run

### xml_parse_fuzzer_UTF-16LE

    # sydr-fuzz -c xml_parse_fuzzer_UTF-16LE.toml run

### xml_parse_fuzzer_UTF-16

    # sydr-fuzz -c xml_parse_fuzzer_UTF-16.toml run

### xml_parse_fuzzer_UTF-8

    # sydr-fuzz -c xml_parse_fuzzer_UTF-8.toml run
