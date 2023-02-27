package main

import (
    "bytes"
    "os"
    "image/gif"
    "fmt"
)

func main() {
    data, _ := os.ReadFile(os.Args[1])
    cfg, err := gif.DecodeConfig(bytes.NewReader(data))
    if err != nil {
        return
    }
    if cfg.Width*cfg.Height > 1e6 {
        return
    }
    img, err := gif.Decode(bytes.NewReader(data))
    if err != nil {
        return
    }
    for c := 1; c <= 256; c += 21 {
        var w bytes.Buffer
        err = gif.Encode(&w, img, &gif.Options{NumColors: c})
        if err != nil {
            panic(err)
        }
        img1, err := gif.Decode(&w)
        if err != nil {
            panic(err)
        }
        b0 := img.Bounds()
        b1 := img1.Bounds()
        if b0.Max.X-b0.Min.X != b1.Max.X-b1.Min.X || b0.Max.Y-b0.Min.Y != b1.Max.Y-b1.Min.Y {
            fmt.Printf("img0: %#v\n", img.Bounds())
            fmt.Printf("img1: %#v\n", img1.Bounds())
            panic("bounds changed")
        }
    }
    return
}
