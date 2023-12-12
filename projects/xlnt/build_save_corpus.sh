cp -r /corpus /save_corpus
for file in /save_corpus/*
do
    sed -i '1s/^/\x00\x05/' $file
done
