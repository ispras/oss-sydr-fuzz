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
DEPS_LIBS="deps/dist/lib/libImath_v_3_1_10_OpenImageIO_v3_2_0.a
    deps/dist/lib/libOpenEXR_v_3_3_5_OpenImageIO_v3_2_0.a \
    deps/dist/lib/libpng16.a \
    deps/dist/lib/libuhdr.a \
    deps/dist/lib/libOpenEXR_v_3_3_5_OpenImageIO_v3_2_0.a \
    deps/dist/lib/libOpenEXRCore_v_3_3_5_OpenImageIO_v3_2_0.a \
    deps/dist/lib/libtiff.a \
    deps/dist/lib/libjpeg.a \
    deps/dist/lib/libwebp.a \
    deps/dist/lib/libwebpdemux.a \
    deps/dist/lib/libwebpmux.a
    deps/dist/lib/libOpenColorIO_v_2_4_2_OIIO.a \
    deps/dist/lib/libIlmThread_v_3_3_5_OpenImageIO_v3_2_0.a \
    deps/dist/lib/libIex_v_3_3_5_OpenImageIO_v3_2_0.a \
    deps/dist/lib/libsharpyuv.a \
    deps/dist/lib/libImath_v_3_1_10_OpenImageIO_v3_2_0.a \
    deps/dist/lib/libexpat.a \
    deps/dist/lib/libpystring.a \
    deps/dist/lib/libyaml-cpp.a \
    deps/dist/lib/libminizip-ng.a \
    deps/dist/lib/libfreetype.a \
    deps/dist/lib/libGIF.a \
    deps/dist/lib/libopenjp2.a \
    -lz -ldl -lm -lpthread"
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
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DBUILD_SHARED_LIBS=0 -DLINKSTATIC=1 -DUSE_PYTHON=0 -DOIIO_BUILD_TESTS=0 -DOIIO_BUILD_TOOLS=0 -DUSE_QT=0 -DOpenImageIO_BUILD_MISSING_DEPS=all ..
LINKSTATIC=1 BUILD_SHARED_LIBS=0 MYCC=$CC MYCXX=$CXX VERBOSE=1 USE_QT=0 USE_PYTHON=0 make -j

# Build fuzz targets.
$CXX $TARGET_FLAGS -g -std=c++17 $INCLUDES ../xmp_decode_fuzz.cpp -o /$TARGET/xmp_decode_$TARGET $MAIN $OIIO_LIBS $DEPS_LIBS

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
