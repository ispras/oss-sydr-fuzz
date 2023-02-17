#!/usr/bin/env python3
# Copyright 2023 ISP RAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

import atheris
import tempfile

with atheris.instrument_imports():
    import torch
    from torch import jit
    import os
    import sys
    import warnings
    from subprocess import CalledProcessError

# Suppress all warnings.
warnings.simplefilter("ignore")

def TestOneInput(input_bytes):
    # make unique file name for parallel fuzzing
    (fd, filename) = tempfile.mkstemp(suffix='.zip')
    os.close(fd)
    with open(filename, 'wb') as f:
        f.write(input_bytes)

    try:
        torch.jit.load(filename)
    except (CalledProcessError, RuntimeError):
        pass
    os.remove(filename)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
