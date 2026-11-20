#!/opt/vllm-venv/bin/python
# SPDX-License-Identifier: Apache-2.0

import sys
import atheris

with atheris.instrument_imports():
    from streaming_parser import check_input


@atheris.instrument_func
def TestOneInput(data):
    check_input(data)


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
