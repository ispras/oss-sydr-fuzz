ARG BASE_IMAGE="sydr/ubuntu22.04-sydr-fuzz"
FROM ${BASE_IMAGE} AS base

ENV RESULT_DIR="/result"

SHELL [ "/bin/bash", "-c" ]

RUN apt-get update && \
    apt-get install -y pkg-config make autoconf autopoint zlib1g-dev zlib1g-dev:i386 \ 
    flex gawk bison parallel && \
    wget https://apt.llvm.org/llvm.sh -O llvm.sh && \
    bash llvm.sh 21 all && \
    rm llvm.sh && \
    cargo install cargo-make

FROM base AS build

ENV RESULT_SRC_DIR="${RESULT_DIR}/elfutils"
ENV RESULT_FUZZ_DIR="${RESULT_DIR}/fuzz"
ENV RESULT_CORPUS_DIR="${RESULT_FUZZ_DIR}/corpus"
ENV RESULT_DIFUZZ_DIR="${RESULT_FUZZ_DIR}/difuzz"
ENV FUZZ_DIR="/oss-sydr-fuzz"

ENV SYDR_FUZZ_DIR="/sydr-fuzz/"
ENV DIFUZZ_DIR="${SYDR_FUZZ_DIR}/sydr/difuzz/"
ENV BUILD_SH="${FUZZ_DIR}/build-single.sh"

RUN mkdir -p ${RESULT_DIR} 

#
# corpus
#
ADD --keep-git-dir=true https://github.com/DavidKorczynski/binary-samples.git /binary-samples
RUN mkdir -p $RESULT_CORPUS_DIR && \
    find /binary-samples -maxdepth 1 -type f -name 'elf-*' \
        -exec cp '{}' $RESULT_CORPUS_DIR \; 

#
# build utils
#
RUN mkdir ${FUZZ_DIR}

COPY sydr.zip ${FUZZ_DIR}
# sydr.zip with difuzz must be present in the directory
RUN unzip ${FUZZ_DIR}/sydr.zip -d ${SYDR_FUZZ_DIR} || if (( $? == 2 )); then true; else false; fi

COPY --exclude=sydr.zip . ${FUZZ_DIR}

#
# multiple src dirs to build in parallel
#
ADD --keep-git-dir=true https://sourceware.org/git/elfutils.git#fb232b56ca4dc37a70fd4e581a0fc2c56dda5e0a ${RESULT_SRC_DIR}
RUN mkdir /difuzz && for build in /libfuzzer /aflpp /cov /sydr /difuzz/dwfl-core /difuzz/libdwfl /difuzz/libelf; do \
        cp -ar --reflink=auto ${RESULT_SRC_DIR} "$build"; \
        cp ${FUZZ_DIR}/fuzz-main.c "$build"; \
    done

#
# build
#
ARG WORKERS=7
ENV WORKERS="${WORKERS}"

RUN /oss-sydr-fuzz/build.sh 

FROM base AS result

COPY --from=build ${RESULT_DIR} ${RESULT_DIR}
