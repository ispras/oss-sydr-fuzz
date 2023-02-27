package main

import (
    "bytes"
    "os"
    "golang.org/x/image/tiff"
)

func main() {
    data, _ := os.ReadFile(os.Args[1])
    cfg, err := tiff.DecodeConfig(bytes.NewReader(data))
    if err != nil {
        return
    }
    if cfg.Width*cfg.Height > 1e6 {
        return
    }
    img, err := tiff.Decode(bytes.NewReader(data))
    if err != nil {
        return
    }
    var w bytes.Buffer
    err = tiff.Encode(&w, img, nil)
    if err != nil {
        panic(err)
    }
}
