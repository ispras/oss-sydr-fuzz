#!/usr/bin/env python3

import atheris
import tempfile

with atheris.instrument_imports():
    import os
    import sys
    import tensorflow as tf

@atheris.instrument_func
def TestOneInput(data):
    (fd, filename) = tempfile.mkstemp(suffix='.wav')
    os.close(fd)
    with open(filename, 'wb') as f:
        f.write(data)
    input_tensor = tf.io.read_file(filename)
    try:
        tf.audio.decode_wav(input_tensor)
    except tf.errors.InvalidArgumentError:
        pass
    except UnicodeDecodeError:
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
