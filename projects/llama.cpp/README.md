# llama.cpp

llama.cpp is a C/C++ project designed for efficient inference of large language models (LLMs)
on a wide range of hardware, including CPUs and various GPUs (NVIDIA, AMD, Intel, Apple Silicon).
Its primary goal is to enable LLM inference with minimal setup and state-of-the-art performance, 
even on devices with limited computational power.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-llama.cpp .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/llama.cpp` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-llama.cpp /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c tomls/fuzz_load_model-lf.toml run

Collect and report coverage:

    # sydr-fuzz -c tomls/fuzz_load_model-lf.toml cov-report

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c tomls/fuzz_load_model-afl++.toml run

## Alternative Fuzz Targets

llama.cpp project has 8 fuzz targets.

### fuzz_apply_template

    # sydr-fuzz -c tomls/fuzz_apply_template-lf.toml run

### fuzz_grammar

    # sydr-fuzz -c tomls/fuzz_grammar-lf.toml run

### fuzz_inference

    # sydr-fuzz -c tomls/fuzz_inference-lf.toml run

### fuzz_json_to_grammar

    # sydr-fuzz -c tomls/fuzz_json_to_grammar-lf.toml run

### fuzz_load_model

    # sydr-fuzz -c tomls/fuzz_load_model-lf.toml run

### fuzz_structurally_created

    # sydr-fuzz -c tomls/fuzz_structurally_created-lf.toml run

### fuzz_structured

    # sydr-fuzz -c tomls/fuzz_structured-lf.toml run

### fuzz_tokenizer (with 10 possible FLAG values: aquila, baichuan, bge, bpe, command_r, deepseek_coder, falcon, gpt_2, spm, qwen2)

    # sydr-fuzz -c tomls/fuzz_tokenizer_FLAG-lf.toml run
