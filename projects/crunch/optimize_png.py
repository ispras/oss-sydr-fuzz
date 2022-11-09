#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 ISP RAS
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
################################################################################

import sys
sys.path.append("/Crunch")

import tempfile
import atheris

with atheris.instrument_imports():
    import os
    import sys
    import shutil
    from subprocess import CalledProcessError

    import src.crunch


def test_crunch_function_optimize_png_unoptimized_file(filename):
    startpath = filename
    testpath = filename + "-crunch"
    # cleanup any existing files from previous tests
    if os.path.exists(testpath):
        os.remove(testpath)
    src.crunch.optimize_png(startpath)

    # check for optimized file following execution
    assert os.path.exists(testpath) is True

    # cleanup optimized file produced by this test
    if os.path.exists(testpath):
        os.remove(testpath)


def TestOneInput(data):
    # make unique file name for for parallel fuzzing
    (_, filename) = tempfile.mkstemp()
    f = open(filename, "wb")
    f.write(data)
    f.close()
    try:
        test_crunch_function_optimize_png_unoptimized_file(filename)
    except CalledProcessError:
        pass
    os.remove(filename)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
