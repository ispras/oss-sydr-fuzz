package main

import (
    "bytes"
    "os"
    "image/jpeg"
    "reflect"
)

func main() {
    data, _ := os.ReadFile(os.Args[1])
    cfg, err := jpeg.DecodeConfig(bytes.NewReader(data))
    if err != nil {
        return
    }
    if cfg.Width*cfg.Height > 1e6 {
        return
    }
    img, err := jpeg.Decode(bytes.NewReader(data))
    if err != nil {
        return
    }
    for q := 0; q <= 100; q += 10 {
        var w bytes.Buffer
        err = jpeg.Encode(&w, img, &jpeg.Options{q})
        if err != nil {
            panic(err)
        }
        img1, err := jpeg.Decode(&w)
        if err != nil {
            panic(err)
        }
        if !reflect.DeepEqual(img.Bounds(), img1.Bounds()) {
            panic("bounds changed")
        }
    }
    return
}
