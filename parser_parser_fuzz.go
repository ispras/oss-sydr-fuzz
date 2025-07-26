//go:build gofuzz
// +build gofuzz

package fuzz

import (
	"bytes"
	
	"github.com/ollama/ollama/parser"
)

func FuzzParseFile(data []byte) int {
	_, err := parser.ParseFile(bytes.NewReader(data))
	if err != nil {
		return 0
	}
	return 1
}
