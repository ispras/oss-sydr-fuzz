#!/bin/bash

mkdir -p /proto/corpus

# Create corpus in protobuf format
for filename in /corpus/*.json; do
    echo "";
    echo "Try to process: ${filename}";
    name=${filename##*}
    /pack/json_packer "${filename}" "/proto${filename}.pb" "--to-proto" || true;
done
