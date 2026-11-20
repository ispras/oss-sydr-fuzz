# vLLM

vLLM is an open-source library for large language model inference and serving.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-vllm .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/vllm` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-vllm /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

## Fuzz tagrets:

  * streaming_parser_engine
  * token_id_scanner
  * incremental_lexer

## Fuzzing

Run fuzzing:

    # sydr-fuzz -c parser.toml run

Minimize the corpus:

    # sydr-fuzz -c parser.toml cmin

Collect coverage:

    # sydr-fuzz -c parser.toml pycov html
