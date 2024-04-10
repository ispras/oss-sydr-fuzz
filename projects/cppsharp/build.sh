#!/bin/bash -ex
# Copyright 2024 ISP RAS
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

cd /CppSharp/build

./build.sh clone_llvm
./build.sh build_llvm
./build.sh package_llvm

./build.sh generate -configuration Release -platform x64 -target-framework net8.0

./build.sh -configuration Release -platform x64 -target-framework net8.0

# Make directories for fuzzing and coverage.
mkdir -p /build_fuzz /build_cov
cp /Parser.cs /fuzz.csproj /build_fuzz
cp /Parser.cs /fuzz.csproj /build_cov

# Build target for fuzzing.
cd /build_fuzz
dotnet publish fuzz.csproj -c release -o bin
cp -r /CppSharp/bin/Release_x64/lib bin
cp -r /CppSharp/bin/Release_x64/lib bin/release/net8.0
sharpfuzz bin/CppSharp.AST.dll
sharpfuzz bin/CppSharp.Parser.CSharp.dll
sharpfuzz bin/CppSharp.Parser.dll
sharpfuzz bin/CppSharp.Runtime.dll
sharpfuzz bin/CppSharp.dll

# Build target for coverage.
cd /build_cov
dotnet build
cp -r /CppSharp/bin/Release_x64/lib bin/Debug/net8.0

# Get corpus.
mkdir /corpus
cd /Cpp-Primer
cp -R -f -n */*.cpp */*.h */*/*.cpp */*/*.h /corpus
