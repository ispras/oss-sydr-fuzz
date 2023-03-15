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

with atheris.instrument_imports():
    import tensorflow as tf
    import numpy as np
    import math
    import os
    import sys
    import warnings
    from subprocess import CalledProcessError

# Suppress all warnings.
warnings.simplefilter("ignore")

def TestOneInput(input_bytes):
    input_bytes = list(input_bytes)
    size = len(input_bytes)
    img_h = math.floor((size / 3) ** 0.5)
    if img_h == 0:
        img_w = img_h
    else:
        img_w = math.floor(size / (3 * img_h))

    data = input_bytes[:img_h * img_w * 3]
    np_arr = np.array(data, dtype=np.float32)
    np_arr = np_arr.reshape((img_h, img_w, 3))
    tensor = tf.convert_to_tensor(np_arr, dtype=tf.float32)

    try:
        tf.image.rgb_to_hsv(tensor)
    except CalledProcessError:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

