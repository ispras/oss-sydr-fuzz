# NTP

The Network Time Protocol (NTP) is a networking protocol for clock synchronization between computer systems over packet-switched, variable-latency data networks.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-ntp .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/ntp` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-ntp /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c ntpd_receive.toml run

Get LCOV HTML coverage report:

    # sydr-fuzz -c ntpd_receive.toml cov-export -- -format=lcov > ntpd_receive.lcov
    # genhtml -o ntpd_receive-html ntpd_receive.lcov

## Minimize corpus

    # sydr-fuzz -c ntpd_receive.toml cmin

## Collect and Report coverage

    # sydr-fuzz -c ntpd_receive.toml cov-report

## Check Security Predicates

Check security predicates on new corpus:

    # sydr-fuzz -c ntpd_receive.toml security

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c ntpd_receive-afl++.toml run
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
