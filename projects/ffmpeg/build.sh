#!/bin/bash -ex
# Copyright 2016 Google Inc.
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

export OUT="/"

if [[ $CONFIG = "libfuzzer" ]]
then
      export CC="clang"
      export CXX="clang++"
      export FFMPEG_CFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,undefined,float-divide-by-zero"
      export LDFLAGS="-g -fsanitize=fuzzer-no-link,address,integer,bounds,null,float-divide-by-zero"
      export LINK_FLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero \
                         -ldrm -lm -ldl -lXext -lz -lpthread -lrt -L/ffmpeg_deps/lib 
                         -L/ffmpeg_deps/lib/alsa-lib/smixer/ -L/ffmpeg_deps/lib/vdpau/ \
                         -I/ffmpeg_deps -I/ffmpeg \
                         -lfdk-aac -lvorbisenc -lvorbisfile -l:smixer-hda.a -l:smixer-ac97.a \
                         -l:smixer-sbase.a -lvdpau_trace -lavfilter -lavdevice -lpostproc \
                         -lva -logg -lswscale -ltheoradec -ltheoraenc -lvpx -lasound -lbz2 \
                         -lswresample -lvorbis -lvdpau -lavutil -lavcodec -lavformat \
                         -ltheora -lva-drm -lxml2 -lopus -fuse-ld=/usr/bin/ld.lld"
      export TARGET_BSF="/target_bsf_fuzzer.c -o /target_bsf_fuzz"
      export TARGET_DEC="-lxcb -lxcb-shm -lxcb -lxcb-xfixes -lxcb -lxcb-shape -lxcb -lX11 \
                         -DFFMPEG_CODEC=AV_CODEC_ID_MPEG1VIDEO -DFUZZ_FFMPEG_VIDEO \
                         /target_dec_fuzzer.c -o /target_dec_fuzz"
      export TARGET_DEM="-DIO_FLAT=0 /target_dem_fuzzer.c -o /target_dem_fuzz"

      mkdir -p $OUT/lib/
      cp /usr/lib/x86_64-linux-gnu/libbz2.so.1.0 $OUT/lib/
      cp /usr/lib/x86_64-linux-gnu/libz.so.1 $OUT/lib/
      bzip2 -f -d alsa-lib-1.1.0.tar.bz2
fi

if [[ $CONFIG = "afl" ]]
then
      export CC="afl-clang-fast"
      export CXX="afl-clang-fast++"
      export FFMPEG_CFLAGS="-g -fsanitize=address,integer,bounds,null,undefined,float-divide-by-zero"
      export LDFLAGS="-g -fsanitize=address,integer,bounds,null,float-divide-by-zero"
      export LINK_FLAGS="-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero \
                         -ldrm -lm -ldl -lXext -lz -lpthread -lrt -L/ffmpeg_deps/lib 
                         -L/ffmpeg_deps/lib/alsa-lib/smixer/ -L/ffmpeg_deps/lib/vdpau/ \
                         -I/ffmpeg_deps -I/ffmpeg \
                         -lfdk-aac -lvorbisenc -lvorbisfile -l:smixer-hda.a -l:smixer-ac97.a \
                         -l:smixer-sbase.a -lvdpau_trace -lavfilter -lavdevice -lpostproc \
                         -lva -logg -lswscale -ltheoradec -ltheoraenc -lvpx -lasound -lbz2 \
                         -lswresample -lvorbis -lvdpau -lavutil -lavcodec -lavformat \
                         -ltheora -lva-drm -lxml2 -lopus -fuse-ld=/usr/bin/ld.lld"
      export TARGET_BSF="/target_bsf_fuzzer.c -o /target_bsf_afl"
      export TARGET_DEC="-lxcb -lxcb-shm -lxcb -lxcb-xfixes -lxcb -lxcb-shape -lxcb -lX11 -lbz2 \
                         -DFFMPEG_CODEC=AV_CODEC_ID_MPEG1VIDEO -DFUZZ_FFMPEG_VIDEO \
                         /target_dec_fuzzer.c -o /target_dec_afl"
      export TARGET_DEM="-DIO_FLAT=0 /target_dem_fuzzer.c -o /target_dem_afl"
fi

if [[ $CONFIG = "sydr" ]]
then
      export CC=clang
      export CXX=clang++
      export FFMPEG_CFLAGS="-g"
      export LDFLAGS="-g"
      export LINK_FLAGS="-g -ldrm -lm -ldl -lXext -lz -lpthread -lrt -L/ffmpeg_deps/lib \
                         -L/ffmpeg_deps/lib/alsa-lib/smixer/ -L/ffmpeg_deps/lib/vdpau/ \
                         -I/ffmpeg_deps -I/ffmpeg \
                         -lfdk-aac -lvorbisenc -lvorbisfile -l:smixer-hda.a -l:smixer-ac97.a \
                         -l:smixer-sbase.a -lvdpau_trace -lavfilter -lavdevice -lpostproc \
                         -lva -logg -lswscale -ltheoradec -ltheoraenc -lvpx -lasound -lbz2 \
                         -lswresample -lvorbis -lvdpau -lavutil -lavcodec -lavformat \
                         -ltheora -lva-drm -lxml2 -lopus -fuse-ld=/usr/bin/ld.lld"
      export TARGET_BSF="-o /target_bsf_sydr target_bsf_fuzzer.o main.o"
      export TARGET_DEC="-lxcb -lxcb-shm -lxcb -lxcb-xfixes -lxcb -lxcb-shape -lxcb -lX11 -lbz2 \
                         -o /target_dec_sydr target_dec_fuzzer.o main.o"
      export TARGET_DEM="-o /target_dem_sydr target_dem_fuzzer.o main.o"
fi

if [[ $CONFIG = "coverage" ]]
then
      export CC=clang
      export CXX=clang++
      export FFMPEG_CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
      export LDFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
      export LINK_FLAGS="$CFLAGS -ldrm -lm -ldl -lXext -lz -lpthread -lrt -L/ffmpeg_deps/lib \
                         -L/ffmpeg_deps/lib/alsa-lib/smixer/ -L/ffmpeg_deps/lib/vdpau/ \
                         -I/ffmpeg_deps \
                         -lfdk-aac -lvorbisenc -lvorbisfile -l:smixer-hda.a -l:smixer-ac97.a \
                         -l:smixer-sbase.a -lvdpau_trace -lavfilter -lavdevice -lpostproc \
                         -lva -logg -lswscale -ltheoradec -ltheoraenc -lvpx -lasound -lbz2 \
                         -lswresample -lvorbis -lvdpau -lavutil -lavcodec -lavformat \
                         -ltheora -lva-drm -lxml2 -lopus -fuse-ld=/usr/bin/ld.lld"
      export TARGET_BSF="-o /target_bsf_cov target_bsf_fuzzer.o main.o"
      export TARGET_DEC="-lxcb -lxcb-shm -lxcb -lxcb-xfixes -lxcb -lxcb-shape -lxcb -lX11 -lbz2 \
                         -o /target_dec_cov target_dec_fuzzer.o main.o"
      export TARGET_DEM="-o /target_dem_cov target_dem_fuzzer.o main.o"
fi

# Disable UBSan vptr since several targets built with -fno-rtti.
export CFLAGS="$LDFLAGS -fno-sanitize=vptr"
export CXXFLAGS="$LDFLAGS -fno-sanitize=vptr"

# Build dependencies.
export FFMPEG_DEPS_PATH=/ffmpeg_deps
rm -rf $FFMPEG_DEPS_PATH
mkdir -p $FFMPEG_DEPS_PATH

export PATH="$FFMPEG_DEPS_PATH/bin:$PATH"
export LD_LIBRARY_PATH="$FFMPEG_DEPS_PATH/lib"

cd /
rm -rf alsa-lib-1.1.0/
tar xf alsa-lib-1.1.0.tar
cd alsa-lib-1.1.0
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static --disable-shared
make clean
make -j$(nproc) all
make install

cd /fdk-aac
autoreconf -fiv
CXXFLAGS="$CXXFLAGS -fno-sanitize=shift-base,signed-integer-overflow" \
./configure --prefix="$FFMPEG_DEPS_PATH" --disable-shared
make clean
make -j$(nproc) all
make install

cd /libva
./autogen.sh
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static --disable-shared
make clean
make -j$(nproc) all
make install

cd /libvdpau
./autogen.sh
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static --disable-shared
make clean
make -j$(nproc) all
make install

cd /libvpx
LDFLAGS="$CXXFLAGS" ./configure --prefix="$FFMPEG_DEPS_PATH" \
        --disable-examples --disable-unit-tests \
        --size-limit=12288x12288 \
        --extra-cflags="-DVPX_MAX_ALLOCABLE_MEMORY=1073741824"
make clean
make -j$(nproc) all
make install

cd /ogg
./autogen.sh
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static --disable-crc
make clean
make -j$(nproc)
make install

cd /opus
./autogen.sh
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static
make clean
make -j$(nproc) all
make install

cd /theora
THEORA_BUILD_ARGS=''
# theora requires ogg, need to pass its location to the "configure" script.
CFLAGS="$CFLAGS -fPIC" LDFLAGS="-L$FFMPEG_DEPS_PATH/lib/" \
      CPPFLAGS="$CXXFLAGS -I$FFMPEG_DEPS_PATH/include/" \
      LD_LIBRARY_PATH="$FFMPEG_DEPS_PATH/lib/" \
      ./autogen.sh
./configure --with-ogg="$FFMPEG_DEPS_PATH" --prefix="$FFMPEG_DEPS_PATH" \
      --enable-static --disable-examples $THEORA_BUILD_ARGS
make clean
make -j$(nproc)
make install

cd /vorbis
./autogen.sh
./configure --prefix="$FFMPEG_DEPS_PATH" --enable-static
make clean
make -j$(nproc)
make install

cd /libxml2
./autogen.sh --prefix="$FFMPEG_DEPS_PATH" --enable-static \
      --without-debug --without-ftp --without-http \
      --without-legacy --without-python
make clean
make -j$(nproc)
make install

# Remove shared libraries to avoid accidental linking against them.
rm $FFMPEG_DEPS_PATH/lib/*.so
rm $FFMPEG_DEPS_PATH/lib/*.so.*

# Build ffmpeg.
cd /ffmpeg

PKG_CONFIG_PATH="$FFMPEG_DEPS_PATH/lib/pkgconfig" ./configure \
        --cc=$CC --cxx=$CXX --ld="$CXX" \
        --extra-cflags="-I$FFMPEG_DEPS_PATH/include $FFMPEG_CFLAGS" \
        --extra-ldflags="-L$FFMPEG_DEPS_PATH/lib $LDFLAGS -std=c++11" \
        --prefix="$FFMPEG_DEPS_PATH" \
        --pkg-config-flags="--static" \
        --libfuzzer=$LIB_FUZZING_ENGINE \
        --optflags=-O1 \
        --enable-gpl \
        --enable-nonfree \
        --enable-libass \
        --enable-libfdk-aac \
        --enable-libfreetype \
        --enable-libopus \
        --enable-libtheora \
        --enable-libvorbis \
        --enable-libvpx \
        --enable-libxml2 \
        --enable-nonfree \
        --disable-muxers \
        --disable-protocols \
        --disable-demuxer=rtp,rtsp,sdp \
        --disable-devices \
        --disable-shared
make clean
make -j$(nproc) install

# Build target.
if [[ $CONFIG = "sydr" || $CONFIG = "coverage" ]]
then
      $CC $LDFLAGS -c -o main.o /opt/StandaloneFuzzTargetMain.c
      $CC $LDFLAGS -I/ffmpeg -c -o target_bsf_fuzzer.o /target_bsf_fuzzer.c
      $CC $LDFLAGS -DFFMPEG_CODEC=AV_CODEC_ID_MPEG1VIDEO -DFUZZ_FFMPEG_VIDEO \
                   -I/ffmpeg -c -o target_dec_fuzzer.o /target_dec_fuzzer.c
      $CC $LDFLAGS -DIO_FLAT=0 -I/ffmpeg -c -o target_dem_fuzzer.o /target_dem_fuzzer.c
fi

# BSF target.
$CC $LINK_FLAGS $TARGET_BSF

# DEC target.
$CC $LINK_FLAGS $TARGET_DEC

# DEM target.
$CC $LINK_FLAGS $TARGET_DEM

# Get corpus.
if [[ $CONFIG = "coverage" ]]
then
      # Download test samples, will be used as seed corpus.
      # DISABLED.
      # TODO: implement a better way to maintain a minimized seed corpora
      # for all targets. As of 2017-05-04 now the combined size of corpora
      # is too big for ClusterFuzz (over 10Gb compressed data).
      export TEST_SAMPLES_PATH=/ffmpeg/fate-suite/
      make fate-rsync SAMPLES=$TEST_SAMPLES_PATH
      #python group_seed_corpus.py $TEST_SAMPLES_PATH /
      rm -rf /corpus
      mkdir /corpus
      cd /ffmpeg/fate-suite
      find * -iname *.m* >> fnd
      find * -iname *.a* >> fnd
      find * -iname *.h* >> fnd
      find * -iname *.b* >> fnd
      find * -iname *.f* >> fnd
      while read p; do cp -r $p /corpus/; done < fnd
fi
