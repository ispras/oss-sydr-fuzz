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


def test_crunch_function_main_single_file(filename, mod):
    startpath = filename
    testpath = filename + "-crunch"
    # cleanup any existing files from previous tests
    if os.path.exists(testpath):
        os.remove(testpath)
    # run main with specify mod
    if mod == 0:
        src.crunch.main([startpath])
    elif mod == 1:
        src.crunch.main(["--gui", startpath])
    elif mod == 2:
        src.crunch.main(["--service", startpath])
    
    # check for optimized file following execution
    assert os.path.exists(testpath) is True
    assert exit_info.value.code == 0

    # cleanup optimized file produced by this test
    if os.path.exists(testpath):
        os.remove(testpath)


def TestOneInput(data):
    mod = 0
    if len(data)!= 0:
        mod = ord(data[:1]) % 3
    # make unique file name for for parallel fuzzing
    (_, filename) = tempfile.mkstemp()
    f = open(filename, "wb")
    if len(data) > 1:
        f.write(data[1:])
    f.close()
    try:
        test_crunch_function_main_single_file(filename, mod)
    except CalledProcessError:
        pass
    except SystemExit:
        pass
    os.remove(filename)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
