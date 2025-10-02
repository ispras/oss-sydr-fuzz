package fuzz

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/ollama/ollama/convert"
	model "github.com/ollama/ollama/model"
	"github.com/ollama/ollama/parser"
	"github.com/ollama/ollama/server"
	"github.com/ollama/ollama/thinking"
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
	if layer.Digest != "" {
		blobPath, _ := getBlobsPath(layer.Digest)
		os.Remove(blobPath)
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

func FuzzAddContent(data []byte) int {
	if len(data) == 0 {
		return -1
	}

	p := &thinking.Parser{
		OpeningTag: "<thinking>",
		ClosingTag: "</thinking>",
	}

	const maxSize = 10 * 1024
	if len(data) > maxSize {
		data = data[:maxSize]
	}

	content := string(data)
	thinkingContent, remaining := p.AddContent(content)

	if !strings.Contains(thinkingContent, content) || !strings.Contains(remaining, content) {
		return 0
	}

	return 1
}

func FuzzParserState(data []byte) int {
	if len(data) == 0 {
		return -1
	}

	p := &thinking.Parser{
		OpeningTag: "<thinking>",
		ClosingTag: "</thinking>",
	}

	content := string(data)
	p.AddContent(content)

	// We can't check internal state directly, so we'll verify behavior instead
	// by checking if the parser correctly handles valid/invalid content
	if strings.Contains(content, "<thinking>") && strings.Contains(content, "</thinking>") {
		// Valid thinking tags - should return some thinking content
		thinkingContent, _ := p.AddContent("")
		if thinkingContent == "" {
			return 0
		}
	} else {
		// No thinking tags - should return empty thinking content
		thinkingContent, _ := p.AddContent("")
		if thinkingContent != "" {
			return 0
		}
	}

	return 1
}

func FuzzEat(data []byte) int {
	if len(data) == 0 {
		return -1
	}

	p := &thinking.Parser{
		OpeningTag: "<thinking>",
		ClosingTag: "</thinking>",
	}

	// Test AddContent which internally uses eat()
	thinkingContent, remaining := p.AddContent(string(data))

	content := string(data)
	if !strings.Contains(thinkingContent, content) || !strings.Contains(remaining, content) {
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
