# h5py

h5py is a Pythonic interface to the HDF5 binary data format.

## Build docker

    $ sudo docker build -t oss-sydr-fuzz-h5py .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/h5py` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-h5py /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c file.toml run

Minimize corpus:

    # sydr-fuzz -c file.toml cmin

Get HTML coverage report:

    # sydr-fuzz -c file.toml pycov html
