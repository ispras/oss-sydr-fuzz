# OSS-Sydr-Fuzz: Hybrid Fuzzing for Open Source Software

This repository is a fork of [OSS-Fuzz](https://github.com/google/oss-fuzz)
project. OSS-Sydr-Fuzz contains open source software targets for sydr-fuzz that
combines fuzzing ([libFuzzer](https://www.llvm.org/docs/LibFuzzer.html), [AFL++](https://github.com/AFLplusplus/AFLplusplus)) with
the power of dynamic symbolic execution
([Sydr](https://sydr-fuzz.github.io)).

## Project Structure

Each open source target project provides:

* Fuzz target for libFuzzer
* Fuzz target for AFL++
* Fuzz target for Sydr
* Target built with llvm-cov
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

Supported projects are located [here](projects). In addition to C/C++ projects Sydr-Fuzz currently supports:
* Rust: capstone-rs, image-rs, goblin, libhtp-rs, vector-rs, rust-regex, serde-json, gdb-command;
* Go: image-go;
* Python: crunch, h5py, msgspec, pillow, pytorch-py, ruamel-yaml, tensorflow-py, ultrajson;
* Java: hsqldb, json-sanitizer;
* JavaScript: fast-xml-parser, node-xml2js.

## Contributing

Feel free to support new fuzz targets. The workflow is following:

1. Compose targets for libFuzzer and Sydr.
2. Prepare build script.
3. Build Dockerfile with all targets.
4. Provide sydr-fuzz configuration files.
5. Write README with commands to run fuzzing.

## Trophies

The list of discovered bugs can be found [here](TROPHIES.md).

## Cite Us

### Sydr-Fuzz: Continuous Hybrid Fuzzing and Dynamic Analysis for Security Development Lifecycle \[[paper](https://arxiv.org/abs/2211.11595)\] \[[demo](https://vishnya.xyz/vishnyakov-isprasopen2022.webm)\] \[[slides](https://vishnya.xyz/vishnyakov-isprasopen2022.pdf)\]

Vishnyakov A., Kuts D., Logunova V., Parygina D., Kobrin E., Savidov G., Fedotov A. Sydr-Fuzz: Continuous Hybrid Fuzzing and Dynamic Analysis for Security Development Lifecycle. 2022 Ivannikov ISPRAS Open Conference (ISPRAS), IEEE, 2022, pp. 111-123. DOI: [10.1109/ISPRAS57371.2022.10076861](https://www.doi.org/10.1109/ISPRAS57371.2022.10076861)

```
@inproceedings{vishnyakov22-sydr-fuzz,
  title = {{{Sydr-Fuzz}}: Continuous Hybrid Fuzzing and Dynamic Analysis for
           Security Development Lifecycle},
  author = {Vishnyakov, Alexey and Kuts, Daniil and Logunova, Vlada and
            Parygina, Darya and Kobrin, Eli and Savidov, Georgy and Fedotov,
            Andrey},
  booktitle = {2022 Ivannikov ISPRAS Open Conference (ISPRAS)},
  pages = {111--123},
  year = {2022},
  publisher = {IEEE},
  doi = {10.1109/ISPRAS57371.2022.10076861},
}
```
