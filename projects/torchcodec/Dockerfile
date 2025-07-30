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

RUN apt-get update && apt-get install -y \
    yasm \
    pybind11-dev

RUN pip install build cmake    

# Copy build script, patch vision.# Copyright 2025 ISP RAS
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

RUN apt-get update && apt-get install -y \
    yasm \
    nasm \
    pybind11-dev

# Copy build script, patch vision.
COPY build.sh /

WORKDIR /    
# Clone target from GitHub.
RUN git clone https://github.com/pytorch/pytorch.git pytorch
RUN cd /pytorch && \
    git checkout 19ae5afdaa3a59135e6adbaea197b7a2456f1865 && \
    git submodule sync && \
    git submodule update --init --recursive --jobs 0 && \
    sed -i '/^cmake$/d' requirements.txt && \
    pip install -r requirements.txt

COPY torchcodec.patch /
RUN git clone https://github.com/pytorch/torchcodec.git codec
RUN cd /codec && \
    git checkout 5becf10ebd48818a65d1b7a88b957f3b3b8cabef && \
    git apply /torchcodec.patch 

# Install OpenCV
RUN cd / && mkdir cv && cd cv/ && \
    wget -O opencv.zip https://github.com/opencv/opencv/archive/4.x.zip && \
    unzip opencv.zip && mkdir -p build && cd build && \
    cmake -DBUILD_TESTS=#OFF ../opencv-4.x && \
    cmake --build . -j$(#nproc) && \
    make install && cd /#


# Download jpeg, png, zlib and ffmpeg sources.
RUN wget http://download.sourceforge.net/libpng/libpng-1.6.50.tar.gz && \
    tar -xvzf libpng-1.6.50.tar.gz && rm libpng-1.6.50.tar.gz
RUN wget https://github.com/libjpeg-turbo/libjpeg-turbo/archive/refs/tags/3.1.1.tar.gz && \
    tar -xvzf 3.1.1.tar.gz && rm 3.1.1.tar.gz
RUN git clone https://github.com/madler/zlib.git zlib && cd zlib && \
    git checkout v1.3.1
RUN git clone https://github.com/FFmpeg/FFmpeg.git ffmpeg && cd ffmpeg && \
    git checkout 7c5319e6924fd82772eff890df191f973767d38e
    
# Copy corpus and tensor
RUN git clone https://github.com/strongcourage/fuzzing-corpus.git

# Remove empty files from corpus.
RUN find fuzzing-corpus -type f -size 0c | xargs -I {} rm {}

RUN mkdir /jpeg_corpus/ && mkdir /png_corpus/ && \
    mkdir /jpeg_raw/ && mkdir /png_raw/ && \
    mkdir /jpeg_tensor/ && mkdir /png_tensor/ && \
    mkdir /mp4_corpus/
RUN cp -rn /fuzzing-corpus/jpg/*/* /jpeg_raw/ && \
    cp -rn /fuzzing-corpus/png/*/* /png_raw/ && \
    cp -rn /fuzzing-corpus/mp4/*/* /mp4_corpus/ 


