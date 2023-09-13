# OpenSSL

OpenSSL is a robust, commercial-grade, full-featured Open Source Toolkit for the
Transport Layer Security (TLS) protocol formerly known as the Secure Sockets
Layer (SSL) protocol. The protocol implementation is based on a full-strength
general purpose cryptographic library, which can also be used stand-alone.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-openssl .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/openssl` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-openssl /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c x509.toml run

Collect and report coverage:

    # sydr-fuzz -c x509.toml cov-report

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c x509-afl++.toml run

## Alternative Fuzz Targets

OpenSSL project has 11 fuzz targets.

### asn1

    # sydr-fuzz -c asn1.toml run

### asn1parse

    # sydr-fuzz -c asn1parse.toml run

### bignum

    # sydr-fuzz -c bignum.toml run

### bndiv

    # sydr-fuzz -c bndiv.toml run

### client

    # sydr-fuzz -c client.toml run

### cmp

    # sydr-fuzz -c cmp.toml run

### cms

    # sydr-fuzz -c cms.toml run

### conf

    # sydr-fuzz -c conf.toml run

### crl

    # sydr-fuzz -c crl.toml run

### ct

    # sydr-fuzz -c ct.toml run

### x509

    # sydr-fuzz -c x509.toml run
