# Open vSwitch

Open vSwitch is a multilayer software switch licensed under the open source
Apache 2 license.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-openvswitch .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/openvswitch` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-openvswitch /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### Flow_extract fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c flow_extract.toml run

Collect and report coverage:

    # sydr-fuzz -c flow_extract.toml cov-report

### Json_parser fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c json_parser.toml run

Collect and report coverage:

    # sydr-fuzz -c json_parser.toml cov-report

### Ofp_print fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c ofp_print.toml run

Collect and report coverage:

    # sydr-fuzz -c ofp_print.toml cov-report

### Odp fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c odp.toml run

Collect and report coverage:

    # sydr-fuzz -c odp.toml cov-report

### Ofctl_parse fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c ofctl_parse.toml run

Collect and report coverage:

    # sydr-fuzz -c ofctl_parse.toml cov-report

### Miniflow fuzzing

Run hybrid fuzzing:

    # sydr-fuzz -c miniflow.toml run

Collect and report coverage:

    # sydr-fuzz -c miniflow.toml cov-report
