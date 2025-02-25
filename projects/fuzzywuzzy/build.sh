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

# Get maven
wget https://dlcdn.apache.org/maven/maven-3/3.9.4/binaries/apache-maven-3.9.4-bin.tar.gz
tar -xvf apache-maven-*-bin.tar.gz
rm apache-maven-*-bin.tar.gz
mv apache-maven-* /opt/

MVN=/opt/apache-maven-3.9.4/bin/mvn
$MVN clean package -Dmaven.javadoc.skip=true -DskipTests=true -Dpmd.skip=true \
    -Dencoding=UTF-8 -Dmaven.antrun.skip=true -Dcheckstyle.skip=true \
    -Denforcer.fail=false org.apache.maven.plugins:maven-shade-plugin:3.2.4:shade
CURRENT_VERSION=$($MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
 -Dexpression=project.version -q -DforceStdout)

cp "package/target/fuzzywuzzy-$CURRENT_VERSION.jar" $OUT/fuzzywuzzy.jar
cp "build/target/fuzzywuzzy-build-$CURRENT_VERSION.jar" $OUT/fuzzywuzzy-build.jar
cp diffutils/target/diffutils-*.jar $OUT/diffutils.jar

JAZZER_API_PATH=/usr/local/lib/jazzer_standalone_deploy.jar
ALL_JARS="fuzzywuzzy.jar:fuzzywuzzy-build.jar:diffutils.jar"
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -maxdepth 1 -name 'Fuzz*.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/
done

# Build corpus

mkdir $OUT/corpus
echo 'UTC1111dsfsdf001211111-00011' > $OUT/corpus/seed1                                                
echo '12345123456' > $OUT/corpus/seed2                                               
echo 'aaaaaaaaaaaa' > $OUT/corpus/seed3
