# POCO

POCO (Portable Components) C++ Libraries are:

  * A collection of C++ class libraries, conceptually similar to the Java Class
Library or the .NET Framework.
  * Focused on solutions to frequently-encountered practical problems.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-poco .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/poco` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host --rm -it -v $PWD:/fuzz oss-sydr-fuzz-poco /bin/bash

### JSON fuzzing

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus_json /fuzz/corpus_json

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c json_parser.toml run -l debug

### XML fuzzing

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus_xml /fuzz/corpus_xml

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c xml_parser.toml run -l debug
