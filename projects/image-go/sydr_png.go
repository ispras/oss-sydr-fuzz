package main

import (
    "bytes"
    "os"
    "image/png"
    "reflect"
    "fmt"
)

func main() {
    data, _ := os.ReadFile(os.Args[1])
    cfg, err := png.DecodeConfig(bytes.NewReader(data))
    if err != nil {
        return
    }
    if cfg.Width*cfg.Height > 1e6 {
        return
    }
    img, err := png.Decode(bytes.NewReader(data))
    if err != nil {
        return
    }
    for _, c := range []png.CompressionLevel{png.DefaultCompression, png.NoCompression, png.BestSpeed, png.BestCompression} {
        var w bytes.Buffer
        e := &png.Encoder{CompressionLevel: c}
        err = e.Encode(&w, img)
        if err != nil {
            panic(err)
        }
        img1, err := png.Decode(&w)
        if err != nil {
            panic(err)
        }
        if !reflect.DeepEqual(img.Bounds(), img1.Bounds()) {
            fmt.Printf("bounds0: %#v\n", img.Bounds())
            fmt.Printf("bounds1: %#v\n", img1.Bounds())
            panic("bounds have changed")
        }
    }
    return
}
