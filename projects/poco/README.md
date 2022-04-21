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

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-poco /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### JSON fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c json_parser.toml run

Collect and report coverage:

    # sydr-fuzz -c json_parser.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c json_parser.toml cov-export -- -format=lcov > json_parser.lcov
    # genhtml -o json_parser-html json_parser.lcov

### XML fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c xml_parser.toml run

Collect and report coverage:

    # sydr-fuzz -c xml_parser.toml cov-report

Get LCOV HTML coverage report:

    # sydr-fuzz -c xml_parser.toml cov-export -- -format=lcov > xml_parser.lcov
    # genhtml -o xml_parser-html xml_parser.lcov
