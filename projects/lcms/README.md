# lcms

Little CMS intends to be an OPEN SOURCE small-footprint color management engine,
with special focus on accuracy and performance.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-lcms .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/lcms` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-lcms /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c cmsIT8_load.toml run

Minimize corpus:

    # sydr-fuzz -c cmsIT8_load.toml cmin

Collect and report coverage:

    # sydr-fuzz -c cmsIT8_load.toml cov-report

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c cmsIT8_load-afl++.toml run

## Alternative Fuzz Targets

Little CMS project has 3 fuzz targets.

### cmsIT8_load

    # sydr-fuzz -c cmsIT8_load.toml run

### cms_overwrite_transform

    # sydr-fuzz -c cms_overwrite_transform.toml run

### cms_transform

    # sydr-fuzz -c cms_transform.toml run

### cms_link

    # sydr-fuzz -c cms_link.toml run
