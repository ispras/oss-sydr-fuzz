#!/usr/bin/python3
# Copyright 2026 ISP RAS
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

import afl, sys, os, io
from pydicom import dcmread, dcmwrite
from pydicom.errors import InvalidDicomError

def TestOneInput(input_bytes):
    try:
        data = io.BytesIO(input_bytes)
        ds = dcmread(data)
        written_data = io.BytesIO()
        ds.save_as(written_data, enforce_file_format=True)
    except InvalidDicomError:
        pass

def main():
    try:
        # Python 3:
        stdin_compat = sys.stdin.buffer
    except AttributeError:
        # There is no buffer attribute in Python 2:
        stdin_compat = sys.stdin    
    
    while afl.loop(10000): 
        TestOneInput(stdin_compat.read())
        sys.stdin.seek(0)
    os._exit(0)

if __name__ == "__main__":
    main()
