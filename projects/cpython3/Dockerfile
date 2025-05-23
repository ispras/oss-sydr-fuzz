# Copyright 2022 ISP RAS
# Copyright 2021 Google LLC
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
###############################################################################

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

RUN apt-get update \
    && apt-get install -y libncursesw5-dev \
    libreadline-dev libssl-dev libgdbm-dev \
    libsqlite3-dev tk-dev libbz2-dev 

RUN git clone https://github.com/python/cpython /cpython3 && \
    cd /cpython3 && git checkout 46857d0b2a2ac6aeb6dcce2bf2c92ddf4abe7496

WORKDIR /cpython3

COPY build.sh .
COPY *.c /
COPY fuzzer.c fuzz_tests.txt /cpython3/Modules/_xxtestfuzz/

# Some AFL-targets are failed to build
ENV AFL_IGNORE_PROBLEMS=1

# Build targets
RUN OUT="/fuzzer" /cpython3/build.sh
RUN OUT="/afl" /cpython3/build.sh
RUN OUT="/sydr" /cpython3/build.sh
RUN OUT="/cov" /cpython3/build.sh

# Prepare fuzzing corpuses
RUN git clone https://github.com/dvyukov/go-fuzz-corpus /corpus
RUN cp /cpython3/Modules/_xxtestfuzz/dictionaries/*.dict /
RUN cp -r /cpython3/Modules/_xxtestfuzz/*_corpus /
RUN mv /fuzz_csv_reader_corpus/* /corpus/csv/corpus/ && rm -rf /fuzz_csv_reader_corpus
RUN mv /fuzz_json_loads_corpus/* /corpus/json/corpus/ && rm -rf /fuzz_json_loads_corpus

ENV AFL_MAP_SIZE=10000000
