# Copyright 2021 Google LLC
# Modifications copyright (C) 2023 ISP RAS
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

FROM sydr/ubuntu20.04-sydr-fuzz
RUN apt-get update && apt-get install -y libssl-dev liblzo2-dev libpam-dev \
    libnl-3-dev libnl-genl-3-dev libcap-ng-dev

RUN git clone https://github.com/google/boringssl.git boringssl && \
    cd boringssl && git checkout 6d3db84c47643271cb553593ee67362be3820874
RUN git clone https://github.com/OpenVPN/openvpn openvpn && \
    cd openvpn && git checkout e8a026ac770592670b0dcf8f81cee6a98b4b4f65
RUN wget https://storage.googleapis.com/openvpn-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/openvpn_fuzz_verify_cert/public.zip

WORKDIR /

COPY fuzz*.c fuzz*.cpp build.sh crypto_patch.txt public.zip /
COPY fuzz*.h /openvpn/src/openvpn/

RUN CONFIG="libfuzzer" /build.sh
RUN CONFIG="afl" /build.sh
RUN CONFIG="sydr" /build.sh
RUN CONFIG="coverage" /build.sh
