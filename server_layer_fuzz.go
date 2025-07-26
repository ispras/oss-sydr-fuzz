//go:build gofuzz
// +build gofuzz

package fuzz

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/ollama/ollama/server"
)

var getBlobsPath = func(digest string) (string, error) {
	dir, err := os.MkdirTemp("", "ollama-blobs-fuzz")
	if err != nil {
		return "", err
	}
	if digest != "" {
		return filepath.Join(dir, digest), nil
	}
	return dir, nil
}

func FuzzNewLayer(data []byte) int {
	const maxSize = 10 * 1024 * 1024
	if len(data) > maxSize {
		return 0
	}

	r := bytes.NewReader(data)
	layer, err := server.NewLayer(r, "application/vnd.docker.image.rootfs.diff.tar.gzip")
	if err != nil {
		return 0
	}

	if layer.Digest != "" {
		blobPath, _ := getBlobsPath(layer.Digest)
		os.Remove(blobPath)
	}

	return 1
}
