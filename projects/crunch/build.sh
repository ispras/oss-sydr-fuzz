#!/bin/bash -eu
# Copyright (C) 2022 ISP RAS
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

make build-dependencies
make install-executable

mkdir /corpus
# add seed corpus.
find . -name "*.png" | grep -v crashers | \
     xargs -I {} cp {} /corpus

mkdir /corpus_main
ls /corpus | xargs -I {} sh -c '(echo -n a && cat /corpus/"{}") > /corpus_main/"{}"'
