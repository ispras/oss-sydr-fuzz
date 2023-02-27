package main

import (
    "bytes"
    "os"
    "golang.org/x/image/webp"
)

func main() {
    data, _ := os.ReadFile(os.Args[1])
    cfg, err := webp.DecodeConfig(bytes.NewReader(data))
    if err != nil {
       return
    }
    if cfg.Width*cfg.Height > 1e6*4 {
       return
    }
    webp.Decode(bytes.NewReader(data))
}
