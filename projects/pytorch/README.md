# PyTorch

PyTorch is an open source machine learning framework based on the Torch library, used for applications such as computer vision and natural language processing.

## Perfomance note

This project uses some perfomance related settings and you can tune this for your machine:

* `MAX_JOBS=100` in build_*.sh – The maximum number of jobs to build the whole project, if your machine has fewer threads, the build system will use all the threads.

* `-rss_limit_mb=30720` in *.toml - Memory usage limit for libFuzzer (in Mb), default 30GB. Use 0 to disable the limit. If an input requires more than this amount of RSS memory to execute, the process is treated as a failure case. The limit is checked in a separate thread every second.

## Build Docker

`$ sudo docker build -t oss-sydr-fuzz-pytorch .`

## Run Hybrid Fuzzing

* Unzip Sydr (`sydr.zip`) in `projects/pytorch` directory:

`$ unzip sydr.zip`

* Run Docker

`$ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-pytorch /bin/bash`

* Change directory to `/fuzz`:

`$ cd /fuzz`

### Fuzz Targets

* dump_fuzz

`$ sydr-fuzz -c dump.toml run`

* load_fuzz

`$ sydr-fuzz -c load.toml run`

* mobile_fuzz

`$ sydr-fuzz -c mobile.toml run`

## Applyed patches

* miniz.* – Updated miniz version to fix segmentation fault.
* stoull.patch – Catch stoull exception to allow the fuzzer go deeper.
