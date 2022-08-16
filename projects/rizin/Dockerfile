FROM sweetvishnya/ubuntu20.04-sydr-fuzz

# Set author of this docker container.
LABEL maintainer="Theodor Arsenij Larionov"

# Install dependencies for build and analysis.
RUN apt-get update && \
    apt-get -y install autoconf automake libtool ninja-build

ENV PATH="${PATH}:/root/.local/bin"

# Install meson
RUN pip3 install --user meson==0.63.0

# Clone target and corpus from github.
RUN mkdir rizin-fuzzing && cd rizin-fuzzing && git clone https://github.com/rizinorg/rizin

WORKDIR /rizin-fuzzing/rizin

# Fix commit. It could be updated later.
RUN git checkout 2166230a9c35b4bc6d3d3bba0084df8ba6fd1577

# Copy patch file that implements fuzzing logic.
COPY build.sh ./
COPY sydr-support-fuzzing.diff ./
COPY rz-fuzz /rizin-fuzzing/rizin/binrz/rz-fuzz

# Build fuzz targets.
RUN ./build.sh

WORKDIR ..

# Create corpus
RUN mkdir ./corpus && git clone https://github.com/rizinorg/rizin-testbins && find ./rizin-testbins -type f -exec cp "{}" /rizin-fuzzing/corpus \; && rm -rf ./rizin-testbins

WORKDIR /fuzz
