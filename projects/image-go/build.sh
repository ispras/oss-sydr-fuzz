#!/bin/bash

# Fix additional package paths
sed -i 's|"internal/byteorder"|"golang.org/x/image/byteorder"|' gif/writer.go
sed -i 's|"image/internal/imageutil"|"golang.org/x/image/imageutil"|' jpeg/reader.go

# webp
go-fuzz-build -libfuzzer -func=FuzzWebp -o webp.a
clang -fsanitize=fuzzer webp.a -o fuzz_webp
go-fuzz-build -func=FuzzWebp -o fuzz_webp.zip
cd cmd/sydr_webp && go build && cd -

# tiff
go-fuzz-build -libfuzzer -func=FuzzTiff -o tiff.a
clang -fsanitize=fuzzer tiff.a -o fuzz_tiff
go-fuzz-build -func=FuzzTiff -o fuzz_tiff.zip
cd cmd/sydr_tiff && go build && cd -

# png
go-fuzz-build -libfuzzer -func=FuzzPng -o png.a
clang -fsanitize=fuzzer png.a -o fuzz_png
go-fuzz-build -func=FuzzPng -o fuzz_png.zip
cd cmd/sydr_png && go build && cd -

# jpeg
go-fuzz-build -libfuzzer -func=FuzzJpeg -o jpeg.a
clang -fsanitize=fuzzer jpeg.a -o fuzz_jpeg
go-fuzz-build -func=FuzzJpeg -o fuzz_jpeg.zip
cd cmd/sydr_jpeg && go build && cd -

# gif
go-fuzz-build -libfuzzer -func=FuzzGif -o gif.a
clang -fsanitize=fuzzer gif.a -o fuzz_gif
go-fuzz-build -func=FuzzGif -o fuzz_gif.zip
cd cmd/sydr_gif && go build && cd -
