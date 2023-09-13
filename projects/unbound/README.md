# Unbound

Unbound is a validating, recursive, caching DNS resolver. It is designed to be
fast and lean and incorporates modern features based on open standards.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-unbound .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/unbound` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-unbound /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### Fuzz_1 fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_1.toml run

Collect and report coverage:

    # sydr-fuzz -c fuzz_1.toml cov-report

### Fuzz_2 fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_2.toml run

Collect and report coverage:

    # sydr-fuzz -c fuzz_2.toml cov-report

### Fuzz_3 fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_3.toml run

Collect and report coverage:

    # sydr-fuzz -c fuzz_3.toml cov-report

### Fuzz_4 fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c fuzz_4.toml run

Collect and report coverage:

    # sydr-fuzz -c fuzz_4.toml cov-report

### Packet_fuzz fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c packet.toml run

Collect and report coverage:

    # sydr-fuzz -c packet.toml cov-report
