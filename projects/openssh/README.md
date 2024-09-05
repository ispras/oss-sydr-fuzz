# OpenSSH

OpenSSH is a complete implementation of the SSH protocol (version 2) for secure
remote login, command execution and file transfer. It includes a client ssh and
server sshd, file transfer utilities scp and sftp as well as tools for key
generation (ssh-keygen), run-time key storage (ssh-agent) and a number of
supporting programs.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-openssh .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/openssh` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-openssh /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c pubkey_fuzz.toml run

Minimize corpus:

    # sydr-fuzz -c pubkey_fuzz.toml cmin

Collect and report coverage:

    # sydr-fuzz -c pubkey_fuzz.toml cov-html

Crash triage with Casr:

    # sydr-fuzz -c pubkey_fuzz.toml casr

## Hybrid Fuzzing with AFL++

    # sydr-fuzz -c pubkey_fuzz-afl++.toml run

## Alternative Fuzz Targets

OpenSSH project has 9 fuzz targets.

### agent

    # sydr-fuzz -c agent_fuzz.toml run

### authopt

    # sydr-fuzz -c authopt_fuzz.toml run

### kex

    # sydr-fuzz -c kex_fuzz.toml run

### privkey

    # sydr-fuzz -c privkey_fuzz.toml run

### pubkey

    # sydr-fuzz -c pubkey_fuzz.toml run

### sig

    # sydr-fuzz -c sig_fuzz.toml run

### sshsig

    # sydr-fuzz -c sshsig_fuzz.toml run

### sshsigopt

    # sydr-fuzz -c sshsigopt_fuzz.toml run

### sshd\_session\_fuzz

    # sydr-fuzz -c sshd_session_fuzz-afl++.toml run
