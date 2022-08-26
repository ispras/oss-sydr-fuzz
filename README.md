# OSS-Sydr-Fuzz: Hybrid Fuzzing for Open Source Software

This repository is a fork of [OSS-Fuzz](https://github.com/google/oss-fuzz)
project. OSS-Sydr-Fuzz contains open source software targets for sydr-fuzz that
combines fuzzing ([libFuzzer](https://www.llvm.org/docs/LibFuzzer.html), [AFL++](https://github.com/AFLplusplus/AFLplusplus)) with
the power of dynamic symbolic execution
([Sydr](https://arxiv.org/abs/2011.09269)).

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

* capstone
* cjson
* expat
* fmt
* freeimage
* image-rs
* lcms
* libcbor
* libjpeg-turbo
* libjpeg
* libpng
* miniz
* miniz-2.0.8
* opencv
* openssl
* openvswitch
* openxlsx
* poco
* poppler
* postgresql
* pytorch
* rapidjson
* re2
* rizin
* sqlite3
* tarantool
* tensorflow
* tinyxml2
* unbound
* torchvision
* xlnt
* ydb
* zlib

## Contributing

Feel free to support new fuzz targets. The workflow is following:

1. Compose targets for libFuzzer and Sydr.
2. Prepare build script.
3. Build Dockerfile with all targets.
4. Provide sydr-fuzz configuration files.
5. Write README with commands to run fuzzing.

## Trophies

* Cairo:
    * <https://gitlab.freedesktop.org/cairo/cairo/-/issues/579>
* FreeImage:
    * <https://sourceforge.net/p/freeimage/bugs/343/>
    * <https://sourceforge.net/p/freeimage/bugs/344/>
    * <https://sourceforge.net/p/freeimage/bugs/345/>
    * <https://sourceforge.net/p/freeimage/bugs/347/>
    * <https://sourceforge.net/p/freeimage/bugs/348/>
    * <https://sourceforge.net/p/freeimage/bugs/349/>
    * <https://sourceforge.net/p/freeimage/bugs/350/>
    * <https://sourceforge.net/p/freeimage/bugs/351/>
* Little-CMS:
    * <https://github.com/mm2/Little-CMS/issues/329>
    * <https://github.com/mm2/Little-CMS/issues/331>
    * <https://github.com/mm2/Little-CMS/issues/333>
* miniz
    * <https://github.com/richgel999/miniz/pull/238>
* miniz-2.0.8 (pytorch third\_party):
    * <https://github.com/pytorch/pytorch/issues/74798>
* OpenJPEG (OpenCV 3rdparty)
    * <https://github.com/opencv/opencv/issues/22284>
* OpenXLSX:
    * <https://github.com/troldal/OpenXLSX/issues/140>
    * <https://github.com/troldal/OpenXLSX/issues/139>
* Poppler:
    * <https://gitlab.freedesktop.org/poppler/poppler/-/issues/1268>
    * <https://gitlab.freedesktop.org/poppler/poppler/-/issues/1269> ([PR](https://gitlab.freedesktop.org/poppler/poppler/-/merge_requests/1221))
* PyTorch:
    * <https://github.com/pytorch/pytorch/issues/77561> (PR: https://github.com/pytorch/pytorch/pull/79192)
    * <https://github.com/pytorch/pytorch/issues/77563> (PR: https://github.com/pytorch/pytorch/pull/79192)
    * <https://github.com/pytorch/pytorch/issues/77573> (PR: https://github.com/pytorch/pytorch/pull/79192)
    * <https://github.com/pytorch/pytorch/issues/77575> (PR: https://github.com/pytorch/pytorch/pull/79192)
    * <https://github.com/pytorch/pytorch/pull/77557>
* Rizin:
    * [rizinorg/rizin@6b118bf](https://github.com/rizinorg/rizin/commit/6b118bf67300182cb068d9e9bb23e85bd052bf86) (PR: https://github.com/rizinorg/rizin/pull/2930)
    * [rizinorg/rizin@eb7e0ef](https://github.com/rizinorg/rizin/commit/eb7e0efe3876a3b9322d0a74860b40010fd6b1cf) (PR: https://github.com/rizinorg/rizin/pull/2930)
    * [rizinorg/rizin@05bbd14](https://github.com/rizinorg/rizin/commit/05bbd147caccc60162d6fba9baaaf24befa281cd) (PR: https://github.com/rizinorg/rizin/pull/2930)
    * [rizinorg/rizin@e5ad689](https://github.com/rizinorg/rizin/commit/e5ad689fc9407ad6f3b53de80c7102c0b1f9d017) (PR: https://github.com/rizinorg/rizin/pull/2930)
    * [rizinorg/rizin@0e86b74](https://github.com/rizinorg/rizin/commit/0e86b74b1d18ca5689dec02976b43eeeac91cca0) (PR: https://github.com/rizinorg/rizin/pull/2930)
    * [rizinorg/rizin@556ca2f](https://github.com/rizinorg/rizin/commit/556ca2f9eef01ec0f4a76d1fbacfcf3a87a44810) ([radareorg/radare2@a665f7f](https://github.com/radareorg/radare2/commit/a665f7fef30325e014af979e69a16150f164c3a2), PR: https://github.com/rizinorg/rizin/pull/2930)
    * [rizinorg/rizin@d4134cb](https://github.com/rizinorg/rizin/commit/d4134cb58c2504846320a1e4d56c9137cf95efc2) (PR: https://github.com/rizinorg/rizin/pull/2930)
    * <https://github.com/rizinorg/rizin/issues/2935>
    * <https://github.com/rizinorg/rizin/issues/2936>
    * <https://github.com/rizinorg/rizin/issues/2952>
    * <https://github.com/rizinorg/rizin/issues/2953>
    * <https://github.com/rizinorg/rizin/issues/2954>
    * <https://github.com/rizinorg/rizin/issues/2955>
    * <https://github.com/rizinorg/rizin/issues/2956>
    * <https://github.com/rizinorg/rizin/issues/2957>
    * <https://github.com/rizinorg/rizin/issues/2958>
    * <https://github.com/rizinorg/rizin/issues/2959>
    * <https://github.com/rizinorg/rizin/issues/2960>
    * <https://github.com/rizinorg/rizin/issues/2961>
    * <https://github.com/rizinorg/rizin/issues/2962>
    * <https://github.com/rizinorg/rizin/issues/2963>
    * <https://github.com/rizinorg/rizin/issues/2964>
    * <https://github.com/rizinorg/rizin/issues/2965>
    * <https://github.com/rizinorg/rizin/issues/2966>
    * <https://github.com/rizinorg/rizin/issues/2967>
    * <https://github.com/rizinorg/rizin/issues/2968>
    * <https://github.com/rizinorg/rizin/issues/2969>
    * <https://github.com/rizinorg/rizin/issues/2970>
    * <https://github.com/rizinorg/rizin/issues/2971>
    * <https://github.com/rizinorg/rizin/issues/2972>
    * <https://github.com/rizinorg/rizin/issues/2973>
    * <https://github.com/rizinorg/rizin/issues/2974>
* Tarantool:
    * <https://github.com/tarantool/tarantool/pull/6614>
    * <https://github.com/tarantool/tarantool/pull/6662>
* TensorFlow:
    * <https://github.com/tensorflow/tensorflow/pull/56455>
* Torchvision
    * <https://github.com/pytorch/vision/pull/6456>
* unbound:
    * <https://github.com/NLnetLabs/unbound/issues/637>
* xlnt:
    * <https://github.com/tfussell/xlnt/issues/592>
    * <https://github.com/tfussell/xlnt/issues/593>
    * <https://github.com/tfussell/xlnt/issues/594>
    * <https://github.com/tfussell/xlnt/issues/595>
    * <https://github.com/tfussell/xlnt/issues/596>
    * <https://github.com/tfussell/xlnt/issues/597>
    * <https://github.com/tfussell/xlnt/issues/598>
    * <https://github.com/tfussell/xlnt/issues/616>
    * <https://github.com/tfussell/xlnt/issues/626>

## Cite Us

### Sydr: Cutting Edge Dynamic Symbolic Execution \[[paper](https://arxiv.org/abs/2011.09269)\] \[[video](https://www.ispras.ru/conf/2020/video/compiler-technology-11-december.mp4#t=6021)\] \[[slides](https://vishnya.xyz/vishnyakov-isprasopen2020.pdf)\]

Vishnyakov A., Fedotov A., Kuts D., Novikov A., Parygina D., Kobrin E., Logunova V., Belecky P., Kurmangaleev Sh. Sydr: Cutting Edge Dynamic Symbolic Execution. 2020 Ivannikov ISPRAS Open Conference (ISPRAS), IEEE, 2020, pp. 46-54. DOI: [10.1109/ISPRAS51486.2020.00014](https://doi.org/10.1109/ISPRAS51486.2020.00014)

```
@inproceedings{vishnyakov20,
  title = {Sydr: Cutting Edge Dynamic Symbolic Execution},
  author = {Vishnyakov, Alexey and Fedotov, Andrey and Kuts, Daniil and Novikov,
            Alexander and Parygina, Darya and Kobrin, Eli and Logunova, Vlada
            and Belecky, Pavel and Kurmangaleev, Shamil},
  booktitle = {2020 Ivannikov ISPRAS Open Conference (ISPRAS)},
  pages = {46--54},
  year = {2020},
  publisher = {IEEE},
  doi = {10.1109/ISPRAS51486.2020.00014},
}
```
