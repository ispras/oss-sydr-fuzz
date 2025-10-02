# Ollama

Ollama is an application which lets you run offline large language models locally.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-ollama .

## Build LibAFL-DiFuzz Docker

Pass `sydr.zip` as an argument:

    $ sudo docker build --build-arg SYDR_ARCHIVE="sydr.zip" -t oss-sydr-fuzz-libafl-ollama -f ./Dockerfile_libafl .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/ollama` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-ollama /bin/bash

Run docker for LibAFL-DiFuzz:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libafl-ollama /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c convert_tokenizer-lf.toml run

Run hybrid fuzzing with LibAFL-DiFuzz:

    # sydr-fuzz -c convert_tokenizer-libafl.toml run

Minimize corpus (only for libfuzzer):

    # sydr-fuzz -c convert_tokenizer-lf.toml cmin

Collect coverage:

    # sydr-fuzz -c convert_tokenizer-lf.toml cov-html
    # sydr-fuzz -c convert_tokenizer-libafl.toml cov-html

## Alternative Fuzz Targets

Ollama project has 10 fuzz targets.

### convert_vocabulary (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c convert_vocabulary-lf.toml run

### convert_vocabulary (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c convert_vocabulary-libafl.toml run

### server_manifest (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c server_manifest-lf.toml run

### server_manifest (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c server_manifest-libafl.toml run

### server_newlayer (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c server_newlayer-lf.toml run

### server_newlayer (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c server_newlayer-libafl.toml run

### thinking_content (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c thinking_content-lf.toml run

### thinking_content (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c thinking_content-libafl.toml run

### thinking_state (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c thinking_state-lf.toml run

### thinking_state (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c thinking_state-libafl.toml run

### thinking_eat (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c thinking_eat-lf.toml run

### thinking_eat (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c thinking_eat-libafl.toml run

### parser_parsefile (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c parser_parsefile-lf.toml run

### parser_parsefile (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c parser_parsefile-libafl.toml run

### harmony_parser (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c harmony_parser-lf.toml run

### harmony_parser (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c harmony_parser-libafl.toml run

### wordpiece (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c wordpiece-lf.toml run

### wordpiece (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c wordpiece-libafl.toml run
