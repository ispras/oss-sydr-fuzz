ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

RUN apt-get update && \
    apt-get install -y pkg-config make autoconf autopoint zlib1g-dev zlib1g-dev:i386 flex gawk bison

RUN git clone --depth 1 https://git.sr.ht/~sourceware/elfutils
WORKDIR elfutils
COPY build.sh *.c *.zip /

RUN cd / && /build.sh
