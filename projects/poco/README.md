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

Collect coverage:

    # mkdir /fuzz/json_parser-out/coverage && cd /fuzz/json_parser-out/coverage
    # for filename in /fuzz/json_parser-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /json_parser_cov "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /json_parser_cov -instr-profile=cov.profdata

### XML fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c xml_parser.toml run

Collect coverage:

    # mkdir /fuzz/xml_parser-out/coverage && cd /fuzz/xml_parser-out/coverage
    # for filename in /fuzz/xml_parser-out/corpus/*; do LLVM_PROFILE_FILE="cov_%p.profraw" /xml_parser_cov "$filename"; done
    # llvm-profdata merge  *.profraw -o cov.profdata
    # llvm-cov report /xml_parser_cov -instr-profile=cov.profdata
