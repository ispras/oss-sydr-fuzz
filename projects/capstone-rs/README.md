# capstone-rs

Bindings to the capstone library disassembly framework.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-capstone-rs .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/capstone-rs` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-capstone-rs /bin/bash

### Run Fuzzing

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c target_disasm_x86_64.toml run
