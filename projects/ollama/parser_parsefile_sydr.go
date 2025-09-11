package main

import "os"

func main() {
	data, _ := os.ReadFile(os.Args[1])
	FuzzParseFile(data)
}
