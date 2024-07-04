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

with atheris.instrument_imports():
  from langchain_community.document_loaders import TextLoader
  from langchain_community.vectorstores import FAISS
  from langchain_community.embeddings import DeterministicFakeEmbedding
  from langchain_text_splitters import CharacterTextSplitter
  from langchain_core.documents.base import Document
  import sys
  import warnings

# Suppress all warnings.
warnings.simplefilter("ignore")

@atheris.instrument_func
def TestOneInput(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  data = fdp.ConsumeString(sys.maxsize)
  if len(data) < 10:
    return
  bound = len(data) // 10 * 9
  text, query = data[:bound], data[bound:]

  try:
    documents = [Document(text)]
    text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
    texts = text_splitter.split_documents(documents)
    if not texts:
      return
    embeddings = DeterministicFakeEmbedding(size=3)
    vectorstore = FAISS.from_documents(texts, embeddings)
    retriever = vectorstore.as_retriever()
    retriever.invoke(query)
    retriever = vectorstore.as_retriever(search_type="mmr")
    retriever.invoke(query)
    retriever = vectorstore.as_retriever(
        search_type="similarity_score_threshold",
        search_kwargs={"score_threshold": 0.5, "k": 3}
    )
    retriever.invoke(query)
  except UnicodeEncodeError:
      pass
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
