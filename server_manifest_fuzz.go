//go:build gofuzz
// +build gofuzz

package fuzz

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/ollama/ollama/server"
	"github.com/ollama/ollama/types/model"
)

var getManifestPath = func() (string, error) {
	return os.MkdirTemp("", "ollama-manifest-fuzz")
}

func FuzzParseNamedManifest(data []byte) int {
	const maxSize = 100 * 1024
	if len(data) > maxSize {
		return 0
	}

	var manifest struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Config        struct {
			MediaType string `json:"mediaType"`
			Size      int64  `json:"size"`
			Digest    string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			MediaType string `json:"mediaType"`
			Size      int64  `json:"size"`
			Digest    string `json:"digest"`
		} `json:"layers"`
	}

	if err := json.Unmarshal(data, &manifest); err != nil {
		return 0
	}

	name := model.Name{
		Host:      "registry.ollama.ai",
		Namespace: "library",
		Model:     "fuzz-test",
		Tag:       "latest",
	}

	manifestDir, err := getManifestPath()
	if err != nil {
		return 0
	}
	defer os.RemoveAll(manifestDir)

	manifestPath := filepath.Join(manifestDir, name.Filepath())
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0755); err != nil {
		return 0
	}

	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		return 0
	}

	if _, err := server.ParseNamedManifest(name); err != nil {
		return 0
	}

	return 1
}
