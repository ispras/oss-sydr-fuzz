ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

RUN apt-get update && apt-get install -y make autoconf automake libtool

# Install brotli.
RUN apt-get install -y libbrotli-dev

# Install zlib.
RUN apt-get update && apt-get install -y zlib1g-dev

RUN git clone --depth 1 https://github.com/yhirose/cpp-httplib.git cpp-httplib && \
    cd cpp-httplib && \
    git checkout 2b8658fa99e6be67d1a8ee2a845f221abe4c5ac8

WORKDIR cpp-httplib
COPY Makefile /cpp-httplib/test/fuzzing
COPY build.sh /cpp-httplib

RUN ./build.sh
