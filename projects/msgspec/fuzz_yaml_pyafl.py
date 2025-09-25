#!/pyAflVenv/bin/python3
# Copyright 2025 ISP RAS
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

import afl, sys, os
import warnings
import msgspec
import yaml

warnings.simplefilter("ignore")

def _ConsumeString(res_len, data):
    s = ""
    if len(data) == 0:
        return s

    if data[0]&1:
        res_len = min(res_len, len(data))
        amt_b = res_len

        for i in range(0, amt_b, 1):
            cur = 0
            for j in range(0, 1):
                cur <<= 8
                cur += data[i+j]
            s += chr(cur)
    elif data[0]&2:
        res_len = min(res_len, len(data) // 2)
        amt_b = res_len * 2

        for i in range(0, amt_b, 2):
            cur = 0
            for j in range(0, 2):
                cur <<= 8
                cur += data[i+j]
            s += chr(cur)
    else:
        res_len = min(res_len, len(data) // 4)
        amt_b = res_len * 4

        for i in range(0, amt_b, 4):
            cur = 0
            for j in range(0, 4):
                cur <<= 8
                cur += data[i+j]
            cur &= 0x1fffff
            if cur&0x100000:
                cur &= ~0x0f0000
            s += chr(cur)
    return s

def TestOneInput(input_bytes):
    data = _ConsumeString(sys.maxsize, input_bytes)
    try:
        msgspec.yaml.decode(data)
    except (msgspec.MsgspecError, ValueError):
        return

def main():
    try:
        # Python 3:
        stdin_compat = sys.stdin.buffer
    except AttributeError:
        # Python 2:
        stdin_compat = sys.stdin

    afl.init()    
    TestOneInput(stdin_compat.read())
    os._exit(0)

if __name__ == "__main__":
    main()
