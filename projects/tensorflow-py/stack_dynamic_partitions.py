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
    import random
    import sys
    import warnings
    from subprocess import CalledProcessError

# Suppress all warnings.
warnings.simplefilter("ignore")

def TestOneInput(input_bytes):
    if len(input_bytes) > 1:
        num_elements = (len(input_bytes) - 1)
        num_partitions = input_bytes[0] % num_elements
        if num_partitions < 2:
            num_partitions = 2
        partitions = [random.randint(0, num_partitions - 1) for i in range(num_elements)]

        np_arr = np.array(list(input_bytes[1:]), dtype=np.int32)
        tensor = tf.convert_to_tensor(np_arr, dtype=tf.int32)

        try:
            tf.ragged.stack_dynamic_partitions(tensor, partitions, num_partitions)
        except CalledProcessError:
            pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

