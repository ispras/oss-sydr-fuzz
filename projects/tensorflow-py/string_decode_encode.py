#!/usr/bin/env python3
#
# Copyright 2023 ISP RAS
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
#
################################################################################

import atheris

with atheris.instrument_imports():
    import sys
    import warnings
    import tensorflow as tf

def TestOneInput(input_bytes):
    bytes = 1
    if len(input_bytes) != 0:
        #Parse bytes param for ConsumeIntList
        bytes = input_bytes[0] % 4 + 1
        
    # Parse input bytes to integer list
    fdp = atheris.FuzzedDataProvider(input_bytes[1:])
    data = fdp.ConsumeIntList(len(input_bytes) // bytes, bytes)

    try:
        string = tf.strings.as_string(data)
        decode = tf.strings.unicode_decode(string, 'UTF-8')
        encode = tf.strings.unicode_encode(decode, 'UTF-8')
    except tf.errors.InvalidArgumentError:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

