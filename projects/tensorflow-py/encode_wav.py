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
    import tensorflow as tf

@atheris.instrument_func
def TestOneInput(data):
    data_lst = list(data)
    data_lst = data_lst[0:len(data_lst) - len(data_lst) % 4]
    data = bytes(data_lst)
    input_tensor = tf.io.decode_raw(data, out_type=tf.float32)
    input_tensor = tf.reshape(input_tensor, [-1, 1])
    try:
        tf.audio.encode_wav(input_tensor, 10)
    except tf.errors.InvalidArgumentError:
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
