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

ARG BASE_IMAGE="sydr/ubuntu20.04-sydr-fuzz"
FROM $BASE_IMAGE

# Clone target from GitHub.
RUN git clone https://github.com/AcademySoftwareFoundation/OpenImageIO.git && cd OpenImageIO && \
    git checkout febafce408199ac5032058189827d08538a5c756 && git submodule update --init --recursive

WORKDIR OpenImageIO

# Copy build script and targets.
COPY fuzz_targets build.sh ./

# Build fuzz targets.
RUN TARGET="sydr" ./build.sh
RUN TARGET="fuzzer" ./build.sh
RUN TARGET="afl" ./build.sh
RUN TARGET="hfuzz" ./build.sh
RUN TARGET="cov" ./build.sh

# Prepare corpus
WORKDIR /
RUN git clone https://github.com/dvyukov/go-fuzz-corpus.git
RUN git clone https://github.com/ImageGlass/sample-images.git

RUN for fmt in "bmp" "jpeg" "jpg" "png" "tiff" "tif" "webp" "ico" "psd" "pbm" "pgm" "ppm" "hdr"; \
    do \
        mkdir /corpus_${fmt}; \
        find /OpenImageIO   -name "*.${fmt}" -type f | xargs -I {} cp {} /corpus_${fmt}; \
        find /sample-images -name "*.${fmt}" -type f | xargs -I {} cp {} /corpus_${fmt}; \
        cp /go-fuzz-corpus/${fmt}/corpus/* /corpus_${fmt}/. || echo 1; \
    done
RUN cp /corpus_jpg/* /corpus_jpeg/. && rm -rf /corpus_jpg
RUN cp /corpus_tif/* /corpus_tiff/. && rm -rf /corpus_tif
RUN mkdir /corpus_pnm && cp /corpus_pbm/* /corpus_pnm && cp /corpus_pgm/* /corpus_pnm && \
    cp /corpus_ppm/* /corpus_pnm && rm -rf /corpus_pbm /corpus_pgm /corpus_ppm

RUN find corpus_* -type f -empty -delete
COPY gen_xmp.py /
RUN pip install pillow && mkdir /corpus_xmp && \
    wget https://github.com/CrossRef/pdfmark/blob/master/test-data/pdfx-xmp-example.xmp -O /corpus_xmp/pdfx-xmp-example.xmp && \
    wget https://github.com/CrossRef/pdfmark/blob/master/test-data/random-xmp-example.xmp -O /corpus_xmp/random-xmp-example.xmp && \
    python3 gen_xmp.py && \
    cp go-fuzz-corpus/xml/corpus/* /corpus_xmp
