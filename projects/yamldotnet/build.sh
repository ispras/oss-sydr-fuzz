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
mkdir -p /build_fuzz /build_cov
cp /Program.cs /fuzz.csproj /build_fuzz
cp /Program.cs /fuzz.csproj /build_cov
rm -rf /Program.cs /fuzz.csproj

# Build target for fuzzing.
cd /build_fuzz
dotnet publish fuzz.csproj -c release -o bin
sharpfuzz bin/YamlDotNet.dll

# Get corpus.
mkdir /corpus
cp /YamlDotNet/YamlDotNet.Test/files/*.yaml /corpus
