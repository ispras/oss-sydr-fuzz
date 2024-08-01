# nginx

nginx is an HTTP and reverse proxy server, a mail proxy server, and a generic TCP/UDP proxy server running on Unix-like operating systems.

## Build Docker

    # sudo docker build -t oss-sydr-fuzz-nginx .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/nginx` directory:

    # unzip sydr.zip

Run Docker:

    # sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-nginx /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c http_request.toml run

Run fuzzing with afl++:

    # sydr-fuzz -c http_request-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c http_request.toml cmin

Collect coverage:

    # sydr-fuzz -c http_request.toml cov-html

Crash triage with Casr:

    # sydr-fuzz -c http_request.toml casr

## Supported Targets

* http_request
