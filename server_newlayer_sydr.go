//go:build gofuzz
// +build gofuzz

package main

import (
	"os"
	"github.com/ollama/ollama/fuzz/server"
)

func main() {
	data, _ := os.ReadFile(os.Args[1])
	fuzz.FuzzNewLayer(data)
}
