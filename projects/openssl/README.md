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

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-openssl /bin/bash

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /openssl/fuzz/corpora/x509 /fuzz/corpus_x509

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c x509.toml run

## Alternative Fuzz Targets

OpenSSL project has 11 fuzz targets.

### asn1

    # cp -r /openssl/fuzz/corpora/asn1 /fuzz/corpus_asn1
    # cd /fuzz
    # sydr-fuzz -c asn1.toml run

### asn1parse

    # cp -r /openssl/fuzz/corpora/asn1parse /fuzz/corpus_asn1parse
    # cd /fuzz
    # sydr-fuzz -c asn1parse.toml run

### bignum

    # cp -r /openssl/fuzz/corpora/bignum /fuzz/corpus_bignum
    # cd /fuzz
    # sydr-fuzz -c bignum.toml run

### bndiv

    # cp -r /openssl/fuzz/corpora/bndiv /fuzz/corpus_bndiv
    # cd /fuzz
    # sydr-fuzz -c bndiv.toml run

### client

    # cp -r /openssl/fuzz/corpora/client /fuzz/corpus_client
    # cd /fuzz
    # sydr-fuzz -c client.toml run

### cmp

    # cp -r /openssl/fuzz/corpora/cmp /fuzz/corpus_cmp
    # cd /fuzz
    # sydr-fuzz -c cmp.toml run

### cms

    # cp -r /openssl/fuzz/corpora/cms /fuzz/corpus_cms
    # cd /fuzz
    # sydr-fuzz -c cms.toml run

### conf

    # cp -r /openssl/fuzz/corpora/conf /fuzz/corpus_conf
    # cd /fuzz
    # sydr-fuzz -c conf.toml run

### crl

    # cp -r /openssl/fuzz/corpora/crl /fuzz/corpus_crl
    # cd /fuzz
    # sydr-fuzz -c crl.toml run

### ct

    # cp -r /openssl/fuzz/corpora/ct /fuzz/corpus_ct
    # cd /fuzz
    # sydr-fuzz -c ct.toml run

### x509

    # cp -r /openssl/fuzz/corpora/x509 /fuzz/corpus_x509
    # cd /fuzz
    # sydr-fuzz -c x509.toml run
