TEST_DATA_VERSION=3.1.0
wget https://github.com/nlohmann/json_test_data/archive/refs/tags/v$TEST_DATA_VERSION.zip
unzip v$TEST_DATA_VERSION.zip
rm v$TEST_DATA_VERSION.zip
for FORMAT in json bjdata bson cbor msgpack ubjson
do
  rm -fr corpus_$FORMAT
  mkdir corpus_$FORMAT
  find json_test_data-$TEST_DATA_VERSION -size -5k -name "*.$FORMAT" -exec cp "{}" "corpus_$FORMAT" \;
done
rm -fr json_test_data-$TEST_DATA_VERSION
rm corpus_json/n_structure_no_data.json # removing empty file from corpus
