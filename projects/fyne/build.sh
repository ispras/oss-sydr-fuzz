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

# entry_text
go-fuzz-build -libfuzzer -func=FuzzEntryText -o entry_text.a
clang -fsanitize=fuzzer entry_text.a -o /fuzz_entry_text
rm entry_text.a

# markdown
go-fuzz-build -libfuzzer -func=FuzzMarkdown -o markdown.a
clang -fsanitize=fuzzer markdown.a -o /fuzz_markdown
rm markdown.a

# svg_bytes
go-fuzz-build -libfuzzer -func=FuzzSVGBytes -o svg_bytes.a
clang -fsanitize=fuzzer svg_bytes.a -o /fuzz_svg_bytes
rm svg_bytes.a

# uri
go-fuzz-build -libfuzzer -func=FuzzURI -o uri.a
clang -fsanitize=fuzzer uri.a -o /fuzz_uri
rm uri.a

# exercise_image
go-fuzz-build -libfuzzer -func=FuzzExerciseImageFile -o exercise_image.a
clang -fsanitize=fuzzer exercise_image.a -o /fuzz_exercise_image
rm exercise_image.a


# Build sydr

cd ..

# image_file
cd cmd/sydr_image_file
go build -o /sydr_image_file

# entry_text
cd ../sydr_entry_text
go build -o /sydr_entry_text

# markdown
cd ../sydr_markdown
go build -o /sydr_markdown

# svg_bytes
cd ../sydr_svg_bytes
go build -o /sydr_svg_bytes

# uri
cd ../sydr_uri
go build -o /sydr_uri

# exercise_image
cd ../sydr_exercise_image
go build -o /sydr_exercise_image


# Build coverage

cd ../..

# image_file
go build -cover -covermode=atomic -coverpkg=./... -o /cov_image_file cmd/sydr_image_file/main.go

# entry_text
go build -cover -covermode=atomic -coverpkg=./... -o /cov_entry_text cmd/sydr_entry_text/main.go

# markdown
go build -cover -covermode=atomic -coverpkg=./... -o /cov_markdown cmd/sydr_markdown/main.go

# svg_bytes
go build -cover -covermode=atomic -coverpkg=./... -o /cov_svg_bytes cmd/sydr_svg_bytes/main.go

# uri
go build -cover -covermode=atomic -coverpkg=./... -o /cov_uri cmd/sydr_uri/main.go

# exercise_image
go build -cover -covermode=atomic -coverpkg=./... -o /cov_exercise_image cmd/sydr_exercise_image/main.go
