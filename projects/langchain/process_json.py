#!/usr/bin/python3

# Copyright 2020 Google LLC
# Copyright 2021 Fraunhofer FKIE
# Modifications copyright (C) 2022 ISP RAS
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
################################################################################

import atheris

with atheris.instrument_imports():
  from langchain_core.output_parsers import JsonOutputParser
  from langchain_text_splitters import RecursiveJsonSplitter
  from langchain_core.exceptions import OutputParserException
  import sys
  import warnings

# Suppress all warnings.
warnings.simplefilter("ignore")

@atheris.instrument_func
def TestOneInput(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  data = fdp.ConsumeString(sys.maxsize)

  try:
    parser = JsonOutputParser()
    splitter = RecursiveJsonSplitter(max_chunk_size=300)
    parsed_data = parser.parse(data) 
    if isinstance(parsed_data, dict):
        splitter.create_documents(texts=[parsed_data], convert_lists=True)
  except OutputParserException as e:
    if 'Invalid json output' not in str(e):
        raise e
  except Exception:
    input_type = str(type(data))
    codepoints = [hex(ord(x)) for x in data]
    sys.stderr.write(
        "Input was {input_type}: {data}\nCodepoints: {codepoints}".format(
            input_type=input_type, data=data, codepoints=codepoints))
    raise


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
