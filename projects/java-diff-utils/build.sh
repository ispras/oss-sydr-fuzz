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
SRC=/src
OUT=/out

cd /java-diff-utils

# Build java-diff-utils
mvn clean package -Dmaven.javadoc.skip=true -DskipTests=true -Dpmd.skip=true \
    -Dencoding=UTF-8 -Dmaven.antrun.skip=true -Dcheckstyle.skip=true \
    -DperformRelease=True org.apache.maven.plugins:maven-shade-plugin:3.2.4:shade
CURRENT_VERSION=$(mvn org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
 -Dexpression=project.version -q -DforceStdout)

cp "./java-diff-utils/target/java-diff-utils-$CURRENT_VERSION.jar" $OUT/java-diff-utils.jar

ALL_JARS='java-diff-utils.jar'

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):/usr/local/lib/jazzer_standalone_deploy.jar

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -name '*FuzzerJZ.java')
do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/
done

cd /

# Build corpus
mkdir -p /corpus
echo '1234512345' > /corpus/seed1
echo '12345123456' > /corpus/seed2
echo '12345a2345' > /corpus/seed3
