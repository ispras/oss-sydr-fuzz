# PyTorch

PyTorch is an open source machine learning framework based on the Torch library, used for applications such as computer vision and natural language processing.

## Build Docker

`docker build -t oss-sydr-fuzz-pytorch .`

## Run Hybrid Fuzzing

* Unzip Sydr (`sydr.zip`) in `projects/pytorch` directory:

`unzip sydr.zip`

* Run Docker

`docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-pytorch /bin/bash`

* Change directory to `/fuzz`:

`cd /fuzz`

### Fuzz Targets

* dump_fuzz

`sydr-fuzz -c dump.toml run`

* load_fuzz

`sydr-fuzz -c load.toml run`

* mobile_fuzz

`sydr-fuzz -c mobile.toml run`

## Applyed patches

* miniz.* – Updated miniz version for fix segmentation fault.
* stoull.patch – Added additional caffe2 version check for deeper fuzzing.
