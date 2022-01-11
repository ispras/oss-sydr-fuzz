# libjpeg-turbo

libjpeg-turbo is a JPEG image codec that uses SIMD instructions to accelerate
baseline JPEG compression and decompression on x86, x86-64, Arm, PowerPC, and
MIPS systems, as well as progressive JPEG compression on x86, x86-64, and Arm
systems. On such systems, libjpeg-turbo is generally 2-6x as fast as libjpeg,
all else being equal. On other types of systems, libjpeg-turbo can still
outperform libjpeg by a significant amount, by virtue of its highly-optimized
Huffman coding routines. In many cases, the performance of libjpeg-turbo rivals
that of proprietary high-speed JPEG codecs.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-libjpeg-turbo .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/libjpeg-turbo` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-libjpeg-turbo /bin/bash

Copy initial seed corpus to `/fuzz` directory:

    # cp -r /corpus_decompress /fuzz/corpus_decompress

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c decompress.toml run

## Alternative Fuzz Targets

libjpeg-turbo project has 3 fuzz targets.

### compress

    # export ASAN_OPTIONS=allocator_may_return_null=1
    # cp -r /corpus_compress /fuzz/corpus_compress
    # cd /fuzz
    # sydr-fuzz -c compress.toml run

### decompress

    # cp -r /corpus_decompress /fuzz/corpus_decompress
    # cd /fuzz
    # sydr-fuzz -c decompress.toml run

### transform

    # cp -r /corpus_decompress /fuzz/corpus_transform
    # cd /fuzz
    # sydr-fuzz -c transform.toml run
