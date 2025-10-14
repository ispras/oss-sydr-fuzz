# fyne

Fyne is an easy-to-use UI toolkit and app API written in Go. It is designed to build applications that run on desktop and mobile devices with a single codebase.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-fyne .

## Build LibAFL-DiFuzz Docker

Pass `sydr.zip` as an argument:

    $ sudo docker build --build-arg SYDR_ARCHIVE="sydr.zip" -t oss-sydr-fuzz-libafl-fyne -f ./Dockerfile_libafl .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/fyne` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-fyne /bin/bash

Run docker for LibAFL-DiFuzz:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libafl-fyne /bin/bash

### Run Fuzzing

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c image_file-lf.toml run

Run hybrid fuzzing with LibAFL-DiFuzz:

    # sydr-fuzz -c image_file-libafl.toml run

## Alternative Fuzz Targets

fyne project has 6 fuzz targets.

### image_raster (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c image_raster-lf.toml run

### image_raster (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c image_raster-libafl.toml run

### image_reader (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c image_reader-lf.toml run

### image_reader (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c image_reader-libafl.toml run

### image_uri (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c image_uri-lf.toml run

### image_uri (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c image_uri-libafl.toml run

### resource_uri (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c resource_uri-lf.toml run

### resource_uri (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c resource_uri-libafl.toml run

### text_layout (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c text_layout-lf.toml run

### text_layout (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c text_layout-libafl.toml run
