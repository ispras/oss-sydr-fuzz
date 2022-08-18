#!/bin/bash

wget https://pumba.intra.ispras.ru/sydr-www/tensorflow/$1_fuzz/$1_fuzz-out.tar.xz
tar -xf $1_fuzz-out.tar.xz
mv $1_fuzz-out/corpus $1
zip $1.zip $1/*
rm -rf $1_fuzz-out.tar.xz $1_fuzz-out $1
