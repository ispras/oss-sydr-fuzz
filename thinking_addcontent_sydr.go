//go:build gofuzz
// +build gofuzz

package main

import (
	"os"
	"github.com/ollama/ollama/fuzz/thinking"
)

func main() {
	data, _ := os.ReadFile(os.Args[1])
	fuzz.FuzzAddContent(data)
}
