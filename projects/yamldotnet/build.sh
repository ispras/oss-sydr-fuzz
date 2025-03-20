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


# Make directories for fuzzing and coverage.
mkdir -p /build_fuzz /build_cov /build_sydr
cp /Program_fuzz.cs /fuzz.csproj /build_fuzz
cp /Program_fuzz.cs /fuzz.csproj /build_cov
cp /Program_sydr.cs /program.csproj /build_sydr

# Build target for fuzzing.
cd /build_fuzz
dotnet publish fuzz.csproj -c release -o bin
sharpfuzz bin/YamlDotNet.dll

# Build aot target for Sydr.
cd /build_sydr
dotnet publish program.csproj -c release -o bin

# Get corpus.
mkdir /corpus
cp /YamlDotNet/YamlDotNet.Test/files/*.yaml /corpus
