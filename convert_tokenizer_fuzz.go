//go:build gofuzz
// +build gofuzz

package convert

import (
	"os"
	"github.com/ollama/ollama/convert"
)

func FuzzParseVocabularyFromTokenizer(data []byte) int {
	tmpDir, err := os.MkdirTemp("", "fuzz-")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(tmpDir)

	tokenizerFile := tmpDir + "/tokenizer.json"
	if err := os.WriteFile(tokenizerFile, data, 0644); err != nil {
		return 0
	}

	fsys := os.DirFS(tmpDir)
	_, err = convert.ParseVocabularyFromTokenizer(fsys)
	if err != nil {
		return 0
	}

	return 1
}

func FuzzParseVocabulary(data []byte) int {
	if FuzzParseVocabularyFromTokenizer(data) == 1 {
		return 1
	}

	tmpDir, err := os.MkdirTemp("", "fuzz-")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(tmpDir)

	modelFile := tmpDir + "/tokenizer.model"
	if err := os.WriteFile(modelFile, data, 0644); err != nil {
		return 0
	}

	fsys := os.DirFS(tmpDir)
	_, err = convert.ParseVocabulary(fsys)
	if err != nil {
		return 0
	}

	return 1
}
