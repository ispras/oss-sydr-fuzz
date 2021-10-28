# OSS-Sydr-Fuzz: Hybrid Fuzzing for Open Source Software

This repository is a fork of [OSS-Fuzz](https://github.com/google/oss-fuzz)
project. OSS-Sydr-Fuzz contains open source software targets for sydr-fuzz that
combines fuzzing ([libFuzzer](https://www.llvm.org/docs/LibFuzzer.html)) with
the power of dynamic symbolic execution
([Sydr](https://www.ispras.ru/en/technologies/sydr/)).

## Project Structure

Each open source target project provides:

* Fuzz target for libFuzzer
* Fuzz target for Sydr
* Build script
* Dictionary
* Initial seed corpus
* Dockerfile that installs dependencies, builds targets, creates initial corpus,
  etc.
* Hybrid fuzzing configuration file for sydr-fuzz
* Instructions to start hybrid fuzzing

NOTE: Some listed above files may not be present or can be gathered from
external repositories.

## Supported Open Source Projects

* lcms
* poco
* postgresql
* rapidjson
* sqlite3
