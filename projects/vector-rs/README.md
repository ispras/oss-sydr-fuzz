# Vector-rs

Vector is a high-performance, end-to-end (agent & aggregator) observability data pipeline that puts you in control of your observability data. Collect, transform, and route all your logs, metrics, and traces to any vendors you want today and any other vendors you may want tomorrow. Vector enables dramatic cost reduction, novel data enrichment, and data security where you need it, not where it is most convenient for your vendors. Additionally, it is open source and up to 10x faster than every alternative in the space.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-vector-rs .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/vector-rs` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-vector-rs /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c parse_aws.toml run
    # sydr-fuzz -c parse_klog.toml run
    # sydr-fuzz -c parse_json.toml run
    # sydr-fuzz -c parse_csv.toml run
    # sydr-fuzz -c parse_xml.toml run
