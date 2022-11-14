#! /bin/bash

cd /
wget http://205.174.165.80/CICDataset/ISCX-URL-2016/Dataset/ISCXURL2016.zip
unzip ISCXURL2016.zip
mkdir url_corpus

i=0
while IFS= read -r line
do
  #echo "$line"
  echo "$line" > "url_corpus/input_$i"
  i=$((i+1))
  if [[ $i -eq 5000 ]]
  then
	  break
  fi
done < ./FinalDataset/URL/phishing_dataset.csv

rm ISCXURL2016.zip
rm -rf FinalDataset
