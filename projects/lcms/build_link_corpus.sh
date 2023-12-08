cp -r /corpus /link_corpus
for file in /link_corpus/*
do
    sed -i '1s/^/\x01\x20\x08/' $file
done
