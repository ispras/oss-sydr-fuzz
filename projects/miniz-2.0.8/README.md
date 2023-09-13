# Miniz

Miniz is a lossless, high performance data compression library in a single
source file that implements the zlib (RFC 1950) and Deflate (RFC 1951)
compressed data format specification standards.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-miniz .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/miniz-2.0.8` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-miniz /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### Checksum fuzzing

    # sydr-fuzz -c checksum.toml run

### Compress fuzzing

    # sydr-fuzz -c compress.toml run

### Flush fuzzing

    # sydr-fuzz -c flush.toml run

### Large fuzzing

    # sydr-fuzz -c large.toml run

### Small fuzzing

    # sydr-fuzz -c small.toml run

### Uncompress2 fuzzing

    # sydr-fuzz -c uncompress2.toml run

### Uncompress fuzzing

    # sydr-fuzz -c uncompress.toml run

### Zip fuzzing

    # sydr-fuzz -c zip.toml run
