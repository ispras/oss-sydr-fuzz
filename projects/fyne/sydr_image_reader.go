package main

import (
    "os"
    "fyne.io/fyne/v2/fuzz"
)

func main() {
    data, _ := os.ReadFile(os.Args[1])
    fuzz.FuzzNewImageFromReader(data)
}

