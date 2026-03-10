#!/bin/bash
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

set -e 

OIIO_LIBS="lib/libOpenImageIO.a lib/libOpenImageIO_Util.a"
INCLUDES="-I/OpenImageIO/src/include \
    -I/OpenImageIO/build_$TARGET/include \
    -I/OpenImageIO/build_$TARGET/deps/dist/include"

if [[ $TARGET == "fuzzer" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -fsanitize=fuzzer-no-link,address,bounds,null,float-divide-by-zero"
    export CXXFLAGS=$CFLAGS
elif [[ $TARGET == "afl" ]]
then
    export CC=afl-clang-fast
    export CXX=afl-clang-fast++
    export CFLAGS="-g -fsanitize=address,bounds,null,float-divide-by-zero"
    export CXXFLAGS=$CFLAGS
elif [[ $TARGET == "hfuzz" ]]
then
    export CC=hfuzz-clang
    export CXX=hfuzz-clang++
    export CFLAGS="-g -fsanitize=address,bounds,null,float-divide-by-zero"
    export CXXFLAGS=$CFLAGS
elif [[ $TARGET == "sydr" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g"
    export CXXFLAGS=$CFLAGS
elif [[ $TARGET == "cov" ]]
then
    export CC=clang
    export CXX=clang++
    export CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
    export CXXFLAGS=$CFLAGS
fi

TARGET_FLAGS=""
MAIN=""
if [[ $TARGET == "fuzzer" || $TARGET == "afl" ]]
then
    TARGET_FLAGS="-fsanitize=fuzzer,address,bounds,null,float-divide-by-zero"
elif [[ $TARGET == "hfuzz" ]]
then
    TARGET_FLAGS="-fsanitize=address,bounds,null,float-divide-by-zero"
else
    $CC $CFLAGS /opt/StandaloneFuzzTargetMain.c -c -o /main_$TARGET.o
    MAIN="/main_$TARGET.o"
    if [[ $TARGET == "cov" ]]
    then
        TARGET_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
    fi
fi

mkdir /$TARGET
mkdir build_$TARGET && cd build_$TARGET

# Build project.
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DBUILD_SHARED_LIBS=0 -DLINKSTATIC=1 -DUSE_PYTHON=0 -DOIIO_BUILD_TESTS=0 -DOIIO_BUILD_TOOLS=1 -DUSE_QT=0 -DOpenImageIO_BUILD_MISSING_DEPS=all ..
LINKSTATIC=1 BUILD_SHARED_LIBS=0 MYCC=$CC MYCXX=$CXX VERBOSE=1 USE_QT=0 USE_PYTHON=0 make -j

# Detect libraries.
IMATH=$(find deps/dist/lib/ -name "libImath_v*")
EXR=$(find deps/dist/lib/ -name "libOpenEXR_v*")
EXRCORE=$(find deps/dist/lib/ -name "libOpenEXRCore_v*")
COLOR=$(find deps/dist/lib/ -name "libOpenColorIO_v*")
THREAD=$(find deps/dist/lib/ -name "libIlmThread_v*")
IEX=$(find deps/dist/lib/ -name "libIex_v*")
GIF=$(find deps/dist/lib/ -name "libGIF.a")
JP2=$(find deps/dist/lib/ -name "libopenjp2.a")

DEPS_LIBS="$IMATH $EXR \
    deps/dist/lib/libpng16.a \
    deps/dist/lib/libuhdr.a \
    $EXR \
    $EXRCORE \
    deps/dist/lib/libtiff.a \
    deps/dist/lib/libjpeg.a \
    deps/dist/lib/libwebp.a \
    deps/dist/lib/libwebpdemux.a \
    deps/dist/lib/libwebpmux.a \
    $COLOR \
    $THREAD \
    $IEX \
    deps/dist/lib/libsharpyuv.a \
    $IMATH \
    deps/dist/lib/libexpat.a \
    deps/dist/lib/libpystring.a \
    deps/dist/lib/libyaml-cpp.a \
    deps/dist/lib/libminizip-ng.a \
    deps/dist/lib/libfreetype.a \
    $GIF \
    $JP2 \
    -lz -ldl -lm -lpthread"

# Build fuzz targets.
XMPFLAG="-DVER_3_1"
if [[ "${EXR: -6}" == "v3_0.a" ]];
then
    XMPFLAG=""
fi
$CXX $TARGET_FLAGS $XMPFLAG -g -std=c++17 $INCLUDES ../xmp_decode_fuzz.cpp -o /$TARGET/xmp_decode_$TARGET $MAIN $OIIO_LIBS $DEPS_LIBS

targets=("bmp" "png" "jpeg" "webp" "tiff" "ico" "psd" "pnm" "hdr")
for fuzztarget in ${targets[@]}; do
    FMT=`echo $fuzztarget | perl -ne 'print uc'`
    suffix="fuzz"
    if [[  $TARGET == "sydr" || $TARGET == "cov" ]]
    then
        suffix="sydr"
    fi
    $CXX $TARGET_FLAGS -g -std=c++17 $INCLUDES ../format_info_${suffix}.cpp    -D${FMT} -o /$TARGET/${fuzztarget}_info_$TARGET    $OIIO_LIBS $DEPS_LIBS
    $CXX $TARGET_FLAGS -g -std=c++17 $INCLUDES ../format_convert_${suffix}.cpp -D${FMT} -o /$TARGET/${fuzztarget}_convert_$TARGET $OIIO_LIBS $DEPS_LIBS
done

cd ..
