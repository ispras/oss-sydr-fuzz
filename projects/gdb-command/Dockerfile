# Copyright 2025 ISP RAS
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

ARG BASE_IMAGE="sydr/ubuntu22.04-sydr-fuzz"
FROM $BASE_IMAGE

# Copy build script.
COPY build_cov.sh build_fuzz.sh build_sydr.sh /

# Clone target from GitHub.
RUN git clone https://github.com/anfedotoff/gdb-command.git

WORKDIR /gdb-command

# Checkout specified commit. It could be updated later.
RUN git checkout 95db52c2358e4b43db8529e83e5b2d20c140b258

RUN sed -i '87ipanic!("reached TP");' /gdb-command/src/stacktrace.rs
RUN sed -i '107ipanic!("reached TP");' /gdb-command/src/stacktrace.rs
RUN sed -i '125ipanic!("reached TP");' /gdb-command/src/stacktrace.rs
RUN sed -i '141ipanic!("reached TP");' /gdb-command/src/stacktrace.rs
RUN sed -i '157ipanic!("reached TP");' /gdb-command/src/stacktrace.rs

# RUN sed -i '25ipanic!("reached TP");' /gdb-command/src/registers.rs

RUN sed -i '50ipanic!("reached TP");' /gdb-command/src/memory.rs

RUN sed -i '27ipanic!("reached TP");' /gdb-command/src/siginfo.rs

RUN sed -i '114ipanic!("reached TP");' /gdb-command/src/mappings.rs

# Build fuzz targets.
RUN ../build_fuzz.sh

COPY build-config/Cargo.toml fuzz/

COPY sydr_*.rs fuzz/fuzz_targets/

WORKDIR fuzz

# Build sydr targets.
RUN cargo clean && /build_sydr.sh

# Build cov targets.
RUN cargo clean && /build_cov.sh

# Create corpus.
RUN mkdir /corpus && echo "aaaaaaaaaaaaaaaaaaaa" > /corpus/in

WORKDIR /
