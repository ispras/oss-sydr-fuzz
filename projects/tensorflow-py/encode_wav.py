#!/usr/bin/env python3

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
