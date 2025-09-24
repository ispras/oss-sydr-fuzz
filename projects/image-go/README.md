# golang/image

This repository holds supplementary Go image libraries.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-image-go .

## Build LibAFL-DiFuzz Docker

Pass `sydr.zip` as an argument:

    $ sudo docker build --build-arg SYDR_ARCHIVE="sydr.zip" -t oss-sydr-fuzz-libafl-image-go -f ./Dockerfile_libafl .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/image-go` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-image-go /bin/bash

Run docker for LibAFL-DiFuzz:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libafl-image-go /bin/bash

### Run Fuzzing

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c tiff-lf.toml run

Run hybrid fuzzing with LibAFL-DiFuzz:

    # sydr-fuzz -c tiff-libafl.toml run

## Alternative Fuzz Targets

golang/image project has 5 fuzz targets.

### gif (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c gif-lf.toml run

### gif (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c gif-libafl.toml run

### jpeg (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c jpeg-lf.toml run

### jpeg (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c jpeg-libafl.toml run

### png (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c png-lf.toml run

### png (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c png-libafl.toml run

### tiff (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c tiff-lf.toml run

### tiff (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c tiff-libafl.toml run

### webp (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c webp-lf.toml run

### webp (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c webp-libafl.toml run
