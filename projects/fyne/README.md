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

### entry_text (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c entry_text-lf.toml run

### entry_text (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c entry_text-libafl.toml run

### exercise_image (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c exercise_image-lf.toml run

### exercise_image (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c exercise_image-libafl.toml run

### uri (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c uri-lf.toml run

### uri (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c uri-libafl.toml run

### svg_bytes (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c svg_bytes-lf.toml run

### svg_bytes (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c svg_bytes-libafl.toml run

### markdown (libfuzzer)

    # cd /fuzz
    # sydr-fuzz -c markdown-lf.toml run

### markdown (LibAFL-DiFuzz)

    # cd /fuzz
    # sydr-fuzz -c markdown-libafl.toml run
