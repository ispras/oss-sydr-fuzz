#!/usr/bin/python3

# Copyright 2024 ISP RAS
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
import tempfile

with atheris.instrument_imports():
  from langchain_community.document_loaders import PyPDFLoader
  from pypdf.errors import EmptyFileError, PdfReadError, PdfStreamError
  import sys
  import warnings

# Suppress all warnings.
warnings.simplefilter("ignore")

@atheris.instrument_func
def TestOneInput(input_bytes):
  fp = tempfile.NamedTemporaryFile()
  fp.write(input_bytes)
  fdp = atheris.FuzzedDataProvider(input_bytes)
  data = fdp.ConsumeString(sys.maxsize)

  try:
    loader = PyPDFLoader(fp.name)
    loader.load_and_split()
  except (EmptyFileError, PdfReadError, PdfStreamError):
      pass
  except Exception:
    input_type = str(type(data))
    codepoints = [hex(ord(x)) for x in data]
    sys.stderr.write(
        "Input was {input_type}: {data}\nCodepoints: {codepoints}".format(
            input_type=input_type, data=data, codepoints=codepoints))
    fp.close()
    raise
  fp.close()

def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
