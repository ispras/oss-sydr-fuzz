#!/bin/bash -eu
# Copyright 2020 Google Inc.

# Build Fuzz targets.
mkdir /fuzzers
mkdir /sydr
mkdir /corpus
make

for f in $(find . -name '*_fuzzer'); do
    cp $f /fuzzers
done

for f in $(find . -name '*_sydr'); do
    cp $f /sydr
done

zip zip_corpus.zip *.c

mv zip_corpus.zip /corpus/

cp zip.dict /zip_fuzzer.dict
