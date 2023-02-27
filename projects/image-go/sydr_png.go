package main


import (
    "os"
    "golang.org/x/image"
)

func main() {
    data, _ := os.ReadFile(os.Args[1])
    image.FuzzPng(data)
}

