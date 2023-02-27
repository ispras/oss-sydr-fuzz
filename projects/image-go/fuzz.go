package image

import (
        "bytes"
        "fmt"
        "golang.org/x/image/webp"
        "golang.org/x/image/tiff"
        "image/png"
        "image/jpeg"
        "image/gif"
        "reflect"
)

func FuzzWebp(data []byte) int {
    cfg, err := webp.DecodeConfig(bytes.NewReader(data))
    if err != nil {
       return 0
    }
    if cfg.Width*cfg.Height > 4000000 {
       return 0
    }
    if _, err := webp.Decode(bytes.NewReader(data)); err != nil {
       return 0
    }
    return 1
}

func FuzzTiff(data []byte) int {
    cfg, err := tiff.DecodeConfig(bytes.NewReader(data))
    if err != nil {
        return 0
    }
    if cfg.Width*cfg.Height > 4000000 {
        return 0
    }
    img, err := tiff.Decode(bytes.NewReader(data))
    if err != nil {
        return 0
    }
    var w bytes.Buffer
    err = tiff.Encode(&w, img, nil)
    if err != nil {
        panic(err)
    }
    return 1
}

func FuzzPng(data []byte) int {
    cfg, err := png.DecodeConfig(bytes.NewReader(data))
    if err != nil {
        return 0
    }
    if cfg.Width*cfg.Height > 4000000 {
        return 0
    }
    img, err := png.Decode(bytes.NewReader(data))
    if err != nil {
        return 0
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
    return 1
}

func FuzzJpeg(data []byte) int {
    cfg, err := jpeg.DecodeConfig(bytes.NewReader(data))
    if err != nil {
        return 0
    }
    if cfg.Width*cfg.Height > 4000000 {
        return 0
    }
    img, err := jpeg.Decode(bytes.NewReader(data))
    if err != nil {
        return 0
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
    return 1
}

func FuzzGif(data []byte) int {
    cfg, err := gif.DecodeConfig(bytes.NewReader(data))
    if err != nil {
        return 0
    }
    if cfg.Width*cfg.Height > 4000000 {
        return 0
    }
    img, err := gif.Decode(bytes.NewReader(data))
    if err != nil {
        return 0
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
    return 1
}
