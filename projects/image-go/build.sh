#!/bin/bash

# webp
go-fuzz-build -libfuzzer -func=FuzzWebp -o webp.a
clang -fsanitize=fuzzer webp.a -o fuzz_webp
cd cmd/sydr_webp && go build && cd -

# tiff
go-fuzz-build -libfuzzer -func=FuzzTiff -o tiff.a
clang -fsanitize=fuzzer tiff.a -o fuzz_tiff
cd cmd/sydr_tiff && go build && cd -

# png
go-fuzz-build -libfuzzer -func=FuzzPng -o png.a
clang -fsanitize=fuzzer png.a -o fuzz_png
cd cmd/sydr_png && go build && cd -

# jpeg
go-fuzz-build -libfuzzer -func=FuzzJpeg -o jpeg.a
clang -fsanitize=fuzzer jpeg.a -o fuzz_jpeg
cd cmd/sydr_jpeg && go build && cd -

# gif
go-fuzz-build -libfuzzer -func=FuzzGif -o gif.a
clang -fsanitize=fuzzer gif.a -o fuzz_gif
cd cmd/sydr_gif && go build && cd -
