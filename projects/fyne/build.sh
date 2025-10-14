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

# Build libfuzzer

cd fuzz

# image_file
go-fuzz-build -libfuzzer -func=FuzzNewImageFromFile -o image_file.a
clang -fsanitize=fuzzer image_file.a -o /fuzz_image_file
rm image_file.a

# image_reader
go-fuzz-build -libfuzzer -func=FuzzNewImageFromReader -o image_reader.a
clang -fsanitize=fuzzer image_reader.a -o /fuzz_image_reader
rm image_reader.a

# image_uri
go-fuzz-build -libfuzzer -func=FuzzNewImageFromURIFile -o image_uri.a
clang -fsanitize=fuzzer image_uri.a -o /fuzz_image_uri
rm image_uri.a

# image_raster
go-fuzz-build -libfuzzer -func=FuzzRasterFromImage -o image_raster.a
clang -fsanitize=fuzzer image_raster.a -o /fuzz_image_raster
rm image_raster.a

# text_layout
go-fuzz-build -libfuzzer -func=FuzzTextLayout -o text_layout.a
clang -fsanitize=fuzzer text_layout.a -o /fuzz_text_layout
rm text_layout.a

# resource_uri
go-fuzz-build -libfuzzer -func=FuzzLoadResourceFromURI -o resource_uri.a
clang -fsanitize=fuzzer resource_uri.a -o /fuzz_resource_uri
rm resource_uri.a


# Build sydr

cd ..

# image_file
cd cmd/sydr_image_file
go build -o /sydr_image_file

# image_reader
cd ../sydr_image_reader
go build -o /sydr_image_reader

# image_uri
cd ../sydr_image_uri
go build -o /sydr_image_uri

# image_raster
cd ../sydr_image_raster
go build -o /sydr_image_raster

# text_layout
cd ../sydr_text_layout
go build -o /sydr_text_layout

# resource_uri
cd ../sydr_resource_uri
go build -o /sydr_resource_uri


# Build coverage

cd ../..

# image_file
go build -cover -covermode=atomic -coverpkg=./... -o /cov_image_file cmd/sydr_image_file/main.go

# image_reader
go build -cover -covermode=atomic -coverpkg=./... -o /cov_image_reader cmd/sydr_image_reader/main.go

# image_uri
go build -cover -covermode=atomic -coverpkg=./... -o /cov_image_uri cmd/sydr_image_uri/main.go

# image_raster
go build -cover -covermode=atomic -coverpkg=./... -o /cov_image_raster cmd/sydr_image_raster/main.go

# text_layout
go build -cover -covermode=atomic -coverpkg=./... -o /cov_text_layout cmd/sydr_text_layout/main.go

# resource_uri
go build -cover -covermode=atomic -coverpkg=./... -o /cov_resource_uri cmd/sydr_resource_uri/main.go
