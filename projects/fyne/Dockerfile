# Copyright (C) 2025 ISP RAS
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

WORKDIR /

RUN apt-get update && apt-get install -y libgl1-mesa-dev pkg-config xorg-dev \
    libxrandr-dev libxi-dev libxcursor-dev libxinerama-dev libgl-dev

RUN git clone https://github.com/fyne-io/fyne.git

WORKDIR /fyne

RUN git checkout 19dcdbdb5f5a9b293a21a29b5235c163345b36d0

RUN sed -i '110ipanic("reached TP")' /fyne/widget/label.go
RUN sed -i '152ipanic("reached TP")' /fyne/widget/label.go

RUN sed -i '176ipanic("reached TP")' /fyne/widget/selectable.go

RUN sed -i '150ipanic("reached TP")' /fyne/canvas/image.go
RUN sed -i '154ipanic("reached TP")' /fyne/canvas/image.go
RUN sed -i '188ipanic("reached TP")' /fyne/canvas/image.go
RUN sed -i '194ipanic("reached TP")' /fyne/canvas/image.go
RUN sed -i '201ipanic("reached TP")' /fyne/canvas/image.go

RUN sed -i '185ipanic("reached TP")' /fyne/widget/markdown.go

RUN sed -i '56ipanic("reached TP")' /fyne/storage/repository/parse.go
RUN sed -i '62ipanic("reached TP")' /fyne/storage/repository/parse.go
RUN sed -i '75ipanic("reached TP")' /fyne/storage/repository/parse.go
RUN sed -i '96ipanic("reached TP")' /fyne/storage/repository/parse.go

RUN sed -i '173ipanic("reached TP")' /fyne/test/app.go
RUN sed -i '35ipanic("reached TP")' /fyne/test/window.go

RUN go get github.com/dvyukov/go-fuzz/go-fuzz-dep

COPY build.sh ./
COPY fuzz.go ./fuzz/

RUN mkdir cmd/sydr_image_file && \
    mkdir cmd/sydr_entry_text && \
    mkdir cmd/sydr_exercise_image && \
    mkdir cmd/sydr_uri && \
    mkdir cmd/sydr_svg_bytes && \
    mkdir cmd/sydr_markdown

COPY sydr_image_file.go cmd/sydr_image_file/main.go
COPY sydr_entry_text.go cmd/sydr_entry_text/main.go
COPY sydr_exercise_image.go cmd/sydr_exercise_image/main.go
COPY sydr_uri.go cmd/sydr_uri/main.go
COPY sydr_svg_bytes.go cmd/sydr_svg_bytes/main.go
COPY sydr_markdown.go cmd/sydr_markdown/main.go

# Build targets.
RUN ./build.sh

WORKDIR /

# Prepare corpus.
RUN git clone --depth=1 https://github.com/dvyukov/go-fuzz-corpus.git
RUN git clone --depth=1 https://github.com/strongcourage/fuzzing-corpus.git
RUN git clone --depth=1 https://github.com/commonmark/commonmark.js.git
RUN mkdir /corpus-image /corpus-text /corpus-svg /corpus-markdown
RUN cp go-fuzz-corpus/png/corpus/* /corpus-image
RUN cp go-fuzz-corpus/jpeg/corpus/* /corpus-image
RUN cp go-fuzz-corpus/gif/corpus/* /corpus-image
RUN cp go-fuzz-corpus/asm/corpus/* /corpus-text
RUN cp go-fuzz-corpus/json/corpus/* /corpus-text
RUN cp fuzzing-corpus/svg/* /corpus-svg
RUN cp commonmark.js/bench/samples/*.md /corpus-markdown
