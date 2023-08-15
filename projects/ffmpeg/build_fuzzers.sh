#!/bin/bash -ex
# Copyright 2016 Google Inc.
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

OUT="/"

# Build the fuzzers.
export CC="clang"
export CXX="clang++"
#export CFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
#export CXXFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"
#export LINKCFLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero"

export CFLAGS="-g -ldrm -lm -ldl -lXext -lz -lpthread -lrt -L/ffmpeg_deps/lib"
export CXXFLAGS="-g -ldrm -lm -ldl -lXext -lz -lpthread -lrt -L/ffmpeg_deps/lib"
export LINKCFLAGS="-g -ldrm -lm -ldl -lXext -lz -lpthread -lrt -L/ffmpeg_deps/lib"

FUZZ_TARGET_SOURCE=/ffmpeg/tools/target_dec_fuzzer.c

export TEMP_VAR_CODEC="AV_CODEC_ID_H264"
export TEMP_VAR_CODEC_TYPE="VIDEO"

cd /ffmpeg

CONDITIONALS=$(grep 'BSF 1$' config_components.h | sed 's/#define CONFIG_\(.*\)_BSF 1/\1/')
for c in $CONDITIONALS; do
      fuzzer_name=ffmpeg_BSF_${c}_fuzzer
      symbol=$(echo $c | sed "s/.*/\L\0/")
      echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${fuzzer_name}.options
      make clean
      make tools/target_bsf_${symbol}_fuzzer
      mv tools/target_bsf_${symbol}_fuzzer $OUT/${fuzzer_name}
      patchelf --set-rpath '$ORIGIN/lib' $OUT/$fuzzer_name
done

# Build fuzzers for decoders.
#CONDITIONALS=$(grep 'DECODER 1$' config_components.h | sed 's/#define CONFIG_\(.*\)_DECODER 1/\1/')
#for c in $CONDITIONALS; do
#      fuzzer_name=ffmpeg_AV_CODEC_ID_${c}_fuzzer
#      symbol=$(echo $c | sed "s/.*/\L\0/")
#      echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${fuzzer_name}.options
#      make tools/target_dec_${symbol}_fuzzer
#      mv tools/target_dec_${symbol}_fuzzer $OUT/${fuzzer_name}
#      patchelf --set-rpath '$ORIGIN/lib' $OUT/$fuzzer_name
#done
#
## Build fuzzer for demuxer
#fuzzer_name=ffmpeg_DEMUXER_fuzzer
#echo -en "[libfuzzer]\nmax_len = 1000000\n" >$OUT/${fuzzer_name}.options
#make tools/target_dem_fuzzer
#mv tools/target_dem_fuzzer $OUT/${fuzzer_name}
#patchelf --set-rpath '$ORIGIN/lib' $OUT/$fuzzer_name
#
## We do not need raw reference files for the muxer
#rm $(find fate-suite -name '*.s16')
#rm $(find fate-suite -name '*.dec')
#rm $(find fate-suite -name '*.pcm')
#
#zip -r $OUT/${fuzzer_name}_seed_corpus.zip fate-suite
#zip -r $OUT/ffmpeg_AV_CODEC_ID_HEVC_fuzzer_seed_corpus.zip fate-suite/hevc fate-suite/hevc-conformance
#
## Build fuzzer for demuxer fed at IO level
#fuzzer_name=ffmpeg_IO_DEMUXER_fuzzer
#make tools/target_io_dem_fuzzer
#mv tools/target_io_dem_fuzzer $OUT/${fuzzer_name}
#patchelf --set-rpath '$ORIGIN/lib' $OUT/$fuzzer_name
#
##Build fuzzers for individual demuxers
#PKG_CONFIG_PATH="$FFMPEG_DEPS_PATH/lib/pkgconfig" ./configure \
#        --cc=$CC --cxx=$CXX --ld="$CXX $LDFLAGS -std=c++11" \
#        --extra-cflags="-I$FFMPEG_DEPS_PATH/include" \
#        --extra-ldflags="-L$FFMPEG_DEPS_PATH/lib" \
#        --prefix="$FFMPEG_DEPS_PATH" \
#        --pkg-config-flags="--static" \
#        --libfuzzer=$LIB_FUZZING_ENGINE \
#        --optflags=-O1 \
#        --enable-gpl \
#        --enable-libxml2 \
#        --disable-muxers \
#        --disable-protocols \
#        --disable-devices \
#        --disable-shared \
#        --disable-encoders \
#        --disable-filters \
#        --disable-muxers \
#        --disable-parsers \
#        --disable-decoders \
#        --disable-hwaccels \
#        --disable-bsfs \
#        --disable-vaapi \
#        --disable-vdpau \
#        --disable-crystalhd \
#        --disable-v4l2_m2m \
#        --disable-cuda_llvm \
#        --enable-demuxers \
#        --disable-demuxer=rtp,rtsp,sdp \
#        $FFMPEG_BUILD_ARGS
#
#CONDITIONALS=$(grep 'DEMUXER 1$' config_components.h | sed 's/#define CONFIG_\(.*\)_DEMUXER 1/\1/')
#
#for c in $CONDITIONALS; do
#      fuzzer_name=ffmpeg_dem_${c}_fuzzer
#      symbol=$(echo $c | sed "s/.*/\L\0/")
#      make tools/target_dem_${symbol}_fuzzer
#      mv tools/target_dem_${symbol}_fuzzer $OUT/${fuzzer_name}
#      patchelf --set-rpath '$ORIGIN/lib' $OUT/$fuzzer_name
#done
#
## Find relevant corpus in test samples and archive them for every fuzzer.
##cd /
##python group_seed_corpus.py $TEST_SAMPLES_PATH $OUT/
