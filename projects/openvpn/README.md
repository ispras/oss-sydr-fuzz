# OpenVPN

OpenVPN provides VPN server solutions for small to mid-size businesses.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-openvpn .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/openvpn` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-openvpn /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing with libfuzzer:

    # sydr-fuzz -c fuzz_dhcp.toml run

Run hybrid fuzzing with afl++:

    # sydr-fuzz -c fuzz_dhcp-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c fuzz_dhcp.toml cmin

Collect coverage:

    # sydr-fuzz -c fuzz_dhcp.toml cov-export -- -format=lcov > fuzz_dhcp.lcov
    # genhtml -o fuzz_dhcp-html fuzz_dhcp.lcov

Check security predicates:

    # sydr-fuzz -c fuzz_dhcp.toml security

Supported fuzz targets:

    * fuzz_base64
    * fuzz_buffer
    * fuzz_dhcp
    * fuzz_list
    * fuzz_misc
    * fuzz_mroute
    * fuzz_packet
    * fuzz_proxy
    * fuzz_route
    * fuzz_verify_cert
