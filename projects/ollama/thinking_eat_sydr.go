package main

import (
	"os"

	"github.com/ollama/ollama/fuzz"
)

func main() {
	data, _ := os.ReadFile(os.Args[1])
	fuzz.FuzzEat(data)
}
