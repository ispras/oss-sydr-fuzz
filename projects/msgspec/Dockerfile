# Copyright (C) 2023 ISP RAS
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

FROM sydr/ubuntu20.04-sydr-fuzz

MAINTAINER Ivan Kapranov

RUN pip install flit

RUN git clone https://github.com/dvyukov/go-fuzz-corpus.git && mkdir corpus_json && cp /go-fuzz-corpus/json/corpus/* corpus_json/

RUN git clone https://github.com/yaml/libyaml && mkdir corpus_yaml && cp /libyaml/examples/* corpus_yaml/

RUN git clone https://github.com/BurntSushi/toml-test.git && mkdir corpus_toml && cp -f -n /toml-test/tests/valid/**/*.toml corpus_toml/

RUN git clone https://github.com/shamaton/msgpack.git && mkdir corpus_msgpack && cp /msgpack/testdata/crashers/* corpus_msgpack/

RUN git clone https://github.com/jcrist/msgspec.git

RUN git clone https://github.com/hukkin/tomli.git

ADD https://pyyaml.org/download/pyyaml/PyYAML-5.3.1.tar.gz /

ADD http://pyyaml.org/download/libyaml/yaml-0.2.5.tar.gz /

RUN tar -xvf yaml-0.2.5.tar.gz &&  rm yaml-0.2.5.tar.gz

RUN tar -xvf PyYAML-5.3.1.tar.gz && rm PyYAML-5.3.1.tar.gz

WORKDIR /msgspec

RUN git checkout 3f16f49743c39e04dced3e3d687d11e1d7572a63

COPY *.dict fuzz_*.py build.sh /

RUN /build.sh
