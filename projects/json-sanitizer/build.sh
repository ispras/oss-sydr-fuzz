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

# Get maven
wget https://dlcdn.apache.org/maven/maven-3/3.9.3/binaries/apache-maven-3.9.3-bin.tar.gz
tar -xvf apache-maven-*-bin.tar.gz
rm apache-maven-*-bin.tar.gz
mv apache-maven-* /opt/
export PATH="$PATH:/opt/apache-maven-3.9.3/bin"

# Build the json-sanitizer jar.
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
CURRENT_VERSION=$(mvn org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
-Dexpression=project.version -q -DforceStdout)
mvn package
cp "target/json-sanitizer-$CURRENT_VERSION.jar" $OUT/json-sanitizer.jar

# The jar files containing the project (separated by spaces).
PROJECT_JARS=json-sanitizer.jar

# Get the fuzzer dependencies (gson).
mvn dependency:copy -Dartifact=com.google.code.gson:gson:2.8.6 -DoutputDirectory=$OUT/

# The jar files containing further dependencies of the fuzz targets (separated
# by spaces).
FUZZER_JARS=gson-2.8.6.jar

# Build fuzzers in $OUT.
ALL_JARS="$PROJECT_JARS $FUZZER_JARS"
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):/usr/local/lib/jazzer_standalone_deploy.jar

# All jars and class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):.:\$this_dir

for fuzzer in $(find $SRC -maxdepth 1 -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer
  mv $SRC/$fuzzer_basename.class $OUT/
done
