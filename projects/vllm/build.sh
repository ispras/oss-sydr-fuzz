#!/usr/bin/env bash
set -euo pipefail

apt-get update
apt-get install -y --no-install-recommends git ca-certificates python3-venv
rm -rf /var/lib/apt/lists/*

python3 -m venv --system-site-packages /opt/vllm-venv
/opt/vllm-venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

SRC=/opt/vllm-src
REV=207d6e6f9a6650056df1bd00ef5b4b5d782045b1

git init -q "$SRC"
git -C "$SRC" remote add origin https://github.com/vllm-project/vllm.git
git -C "$SRC" sparse-checkout init --cone
git -C "$SRC" sparse-checkout set vllm/parser/engine
git -C "$SRC" fetch --depth 1 --filter=blob:none origin "$REV"
git -C "$SRC" checkout --detach FETCH_HEAD

test "$(git -C "$SRC" rev-parse HEAD)" = "$REV"
