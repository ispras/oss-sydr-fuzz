# PyTorch

PyTorch is an open source machine learning framework based on the Torch library, used for applications such as computer vision and natural language processing.

## Build Docker

`$ docker build -t oss-sydr-fuzz-pytorch .`

## Run Hybrid Fuzzing

* Run Docker

`$ docker run --rm -it -v $PWD:/fuzz oss-sydr-fuzz-pytorch bash`

* Change directory to `/fuzz`:

`$ cd /fuzz`

### Fuzz Targets

* dump_fuzz

`$ sydr-fuzz -c dump.toml run`

* load_fuzz

`sydr-fuzz -c load.toml run`

* mobile_fuzz

`sydr-fuzz -c mobile.toml run`
