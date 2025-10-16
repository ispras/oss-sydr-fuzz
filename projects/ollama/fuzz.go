package fuzz

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/ollama/ollama/convert"
	model "github.com/ollama/ollama/model"
	"github.com/ollama/ollama/parser"
	"github.com/ollama/ollama/server"
	"github.com/ollama/ollama/harmony"
	typesmodel "github.com/ollama/ollama/types/model"
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

func FuzzParseFile(data []byte) int {
	_, err := parser.ParseFile(bytes.NewReader(data))
	if err != nil {
		return 0
	}
	return 1
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

	name := typesmodel.Name{
		Host:      "registry.ollama.ai",
		Namespace: "library",
		Model:     "fuzz-test",
		Tag:       "latest",
	}

	manifestDir, err := os.MkdirTemp("", "ollama-manifest-fuzz")
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

func FuzzHarmonyParser(data []byte) int {
	if len(data) == 0 {
		return -1
	}

	parser := harmony.HarmonyParser{
			MessageStartTag: "<|start|>",
			MessageEndTag:   "<|end|>",
			HeaderEndTag:    "<|message|>",
		}
	parser.ParseHeader(string(data))

	gotEvents := parser.AddContent(string(data))
	if len(gotEvents) == 0 {
		return 1
	}

	return 0
}

func FuzzWordPiece(data []byte) int {
	wpm := model.NewWordPiece(
		&model.Vocabulary{
			Values: []string{"[UNK]", "[CLS]", "[SEP]", "▁hello", "▁world", "s", "▁!", "▁@", "▁#", "▁abc", "▁a", "▁b", "▁c", "▁s", "a", "b", "c", "d", "z"},
			AddBOS: true,
			AddEOS: true,
			BOS:    []int32{1},
			EOS:    []int32{2},
		})

	_, err := wpm.Encode(string(data), true)
	if err != nil {
		return 1
	}
	return 0
}
