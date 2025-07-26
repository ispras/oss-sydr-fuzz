//go:build gofuzz
// +build gofuzz

package main

import (
	"os"
	"github.com/ollama/ollama/fuzz/parser"
)

func main() {
	data, _ := os.ReadFile(os.Args[1])
	fuzz.FuzzParseFile(data)
}
