#!/bin/bash -eu
# Copyright 2021 Google LLC
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
SRC=/
OUT=/out
ANT=/ant/apache-ant-1.10.14/bin/ant

mkdir $OUT

pushd ${SRC}/hsqldb-svn/build
$ANT -Dbuild.debug=true hsqldb
cp ../lib/hsqldb.jar $OUT/
popd

ALL_JARS="hsqldb.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):/usr/local/lib/jazzer_standalone_deploy.jar

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

# compile all java files and copy them to $OUT
javac -cp $SRC:$BUILD_CLASSPATH -g $SRC/*.java
cp $SRC/*.class $OUT/

# generate jazzer start script
for fuzzer in $(find $SRC -maxdepth 1 -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $SRC:$BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/
done
