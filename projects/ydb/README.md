# YDB

YDB is an open-source Distributed SQL Database that combines high availability and scalability with strict consistency and ACID transactions.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-ydb .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/ydb` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run -v /etc/localtime:/etc/localtime:ro --privileged --network host --rm -it -v $PWD:/fuzz oss-sydr-fuzz-ydb /bin/bash

Change the directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c base64_lib_fuzz.toml run

Minimize corpus:

    # sydr-fuzz -c base64_lib_fuzz.toml cmin

## Check Security Predicates

Minimize corpus:

    # sydr-fuzz -c base64_lib_fuzz.toml cmin

Check security predicates on new corpus:

    # sydr-fuzz -c base64_lib_fuzz.toml security

## Alternative Fuzz Targets

YDB project has 11 fuzz targets.

### base64_uneven_fuzz

    # sydr-fuzz -c base64_uneven_fuzz.toml run

### cgiparam_fuzz

    # sydr-fuzz -c cgiparam_fuzz.toml run

### cgiparam_fuzz

    # sydr-fuzz -c cgiparam_fuzz.toml run

### dense_map_fuzz

    # sydr-fuzz -c dense_map_fuzz.toml run

### flat_map_fuz

    # sydr-fuzz -c flat_map_fuzz.toml run

### http_fuzz

    # sydr-fuzz -c http_fuzz.toml run

### intrusive_rb_tree_fuzz

    # sydr-fuzz -c intrusive_rb_tree_fuzz.toml run

### json_cpp_fuzz

    # sydr-fuzz -c json_cpp_fuzz.toml run

### json_monlib_fuzz

    # sydr-fuzz -c json_monlib_fuzz.toml run

### prometheus_fuzz

    # sydr-fuzz -c prometheus_fuzz.toml run

### spack_fuzz

    # sydr-fuzz -c spack_fuzz.toml run
