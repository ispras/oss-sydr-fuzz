# Copyright 2023 ISP RAS
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

RUN apt update && apt install zip build-essential libtool autoconf pkg-config zlib1g-dev liblzma-dev -y

RUN curl -LO http://mirrors.kernel.org/ubuntu/pool/main/a/automake-1.16/automake_1.16.5-1.3_all.deb && \
    apt install ./automake_1.16.5-1.3_all.deb

RUN git clone https://gitlab.gnome.org/GNOME/libxml2.git

RUN git clone https://github.com/strongcourage/fuzzing-corpus.git

ADD https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/url.dict /opt/

RUN mkdir xml_corpus && find / -name "*.xml" -exec cp {} xml_corpus/ \;
RUN mkdir html_corpus &&  find / -name "*.html" -exec cp {} html_corpus \;
RUN mkdir schemas_corpus &&  find / -name "*.xsd" -exec cp {} schemas_corpus \;
RUN mkdir xinclude_corpus && cp libxml2/test/XInclude/docs/* xinclude_corpus/ && \
                             cp libxml2/test/XInclude/ents/* xinclude_corpus/ && \
                             cp libxml2/test/XInclude/without-reader/* xinclude_corpus/ 
RUN mkdir xpath_corpus && cp libxml2/test/XPath/tests/*  xpath_corpus/
RUN mkdir regexp_corpus && cp libxml2/fuzz/static_seed/regexp/* regexp_corpus
RUN mkdir uri_corpus && cp libxml2/fuzz/static_seed/uri/* uri_corpus

WORKDIR libxml2

RUN git checkout c7260a47f19e01f4f663b6a56fbdc2dafd8a6e7e

COPY build.sh ./

RUN ./build.sh

WORKDIR /