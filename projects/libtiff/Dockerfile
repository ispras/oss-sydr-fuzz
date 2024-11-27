# Copyright 2023 ISP RAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

RUN git clone https://gitlab.com/libtiff/libtiff && \
    cd libtiff && git checkout cb88a5b6bf1757060ec4d50055fa852fd7830cfe

RUN git clone https://github.com/madler/zlib && \
    cd zlib && git checkout 04f42ceca40f73e2978b50e93806c2a18c1281fc

RUN git clone https://github.com/libjpeg-turbo/libjpeg-turbo && \
    cd libjpeg-turbo && git checkout e429e379b01dde9d1d92b5bbabd2a18ee75d7eaa

RUN git clone https://www.cl.cam.ac.uk/~mgk25/git/jbigkit && \
    cd jbigkit && git checkout 7d3c1bea895d910907e2501fe9165e353eceabae

COPY jbigkit.patch /jbigkit
RUN cd jbigkit && git apply jbigkit.patch

ADD https://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz afl_testcases.tgz

ADD https://raw.githubusercontent.com/google/AFL/debe27037b9444bbf090a0ffbd5d24889bb887ae/dictionaries/tiff.dict tiff.dict

WORKDIR /libtiff

COPY build.sh tiff_read_rgba_fuzzer.cc /

RUN CONFIG="libfuzzer" /build.sh
RUN CONFIG="afl" /build.sh
RUN CONFIG="sydr" /build.sh
RUN CONFIG="coverage" /build.sh

WORKDIR /
