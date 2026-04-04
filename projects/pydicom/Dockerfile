# Copyright (C) 2026 ISP RAS
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

RUN git clone https://github.com/pydicom/pydicom.git pydicom
RUN git clone https://github.com/robyoung/dicom-test-files
RUN mv dicom-test-files/data/pydicom /corpus

COPY build.sh build.sh
COPY fuzzer-pyafl.py fuzzer-pyafl.py

WORKDIR /pydicom

# Checkout specified commit. It could be updated later.
RUN git checkout 50cd981a068c74b01d854c6cac9bb897fe0b74a9

RUN /build.sh