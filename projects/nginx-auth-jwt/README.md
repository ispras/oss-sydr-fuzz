# nginx-auth-jwt

This nginx-auth-jwt is nginx module that implements client authorization by validating the provided JSON Web Token (JWT) using the specified keys.

## Build Docker

    # sudo docker build -t oss-sydr-fuzz-nginx-auth-jwt .

## Run Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/nginx-auth-jwt` directory:

    # unzip sydr.zip

Run Docker:

    # sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-nginx-auth-jwt /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c jwt_parse.toml run

Run fuzzing with afl++:

    # sydr-fuzz -c jwt_parse-afl++.toml run

Minimize corpus:

    # sydr-fuzz -c jwt_parse.toml cmin

Collect coverage:

    # sydr-fuzz -c jwt_parse.toml cov-html

Crash triage with Casr:

    # sydr-fuzz -c jwt_parse.toml casr

## Supported Targets

* jwt_parse
* jwks_parse
* jwt_claim
