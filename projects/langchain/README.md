# LangChain

LangChain is a framework for developing applications powered by large language models (LLMs).

## Build Docker

    # sudo docker build -t oss-sydr-fuzz-langchain .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/langchain` directory:

    # unzip sydr.zip

Run Docker:

    # sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-langchain /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c process_json.toml run

Minimize corpus:

    # sydr-fuzz -c process_json.toml cmin

Collect coverage:

    # sydr-fuzz -c process_json.toml pycov html

## Supported Targets

* process_json
* process_pdf 
* retriever 
