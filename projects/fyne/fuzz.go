package fuzz

import (
    "os"
    "path/filepath"
    "io/ioutil"
    "image"

    "fyne.io/fyne/v2/canvas"
    "fyne.io/fyne/v2/storage"
    "fyne.io/fyne/v2/theme"
    "fyne.io/fyne/v2"
)

func WriteTempFile(data []byte, pattern string) (*os.File, error) {
    tmp, err := ioutil.TempFile("", pattern)
    if err != nil {
        return nil, err
    }
    if _, err := tmp.Write(data); err != nil {
        tmp.Close()
        os.Remove(tmp.Name())
        return nil, err
    }
    if err := tmp.Close(); err != nil {
        os.Remove(tmp.Name())
        return nil, err
    }
    return tmp, nil
}

func FuzzNewImageFromFile(data []byte) int {
	tmp, err := WriteTempFile(data, "fynefile")
    if err != nil {
        return 1
    }
    defer os.Remove(tmp.Name())

    canvas.NewImageFromFile(tmp.Name())
    return 0
}

func FuzzNewImageFromReader(data []byte) int {
	tmp, err := WriteTempFile(data, "fynereader")
    if err != nil {
        return 1
    }
    defer os.Remove(tmp.Name())

    read, err := os.Open(tmp.Name())
	defer read.Close()

	canvas.NewImageFromReader(read, filepath.Base(tmp.Name()))
    return 0
}

func FuzzNewImageFromURIFile(data []byte) int {
	tmp, err := WriteTempFile(data, "fyneuri")
    if err != nil {
        return 1
    }
    defer os.Remove(tmp.Name())

    canvas.NewImageFromURI(storage.NewFileURI(tmp.Name()))
    return 0
}

func FuzzRasterFromImage(data []byte) int {
    if len(data) < 8 {
        return 0
    }

    x0 := int(data[0])
    y0 := int(data[1])
    x1 := x0 + int(data[2]) + 1
    y1 := y0 + int(data[3]) + 1

    source := image.Rect(x0, y0, x1, y1)
    dest := canvas.NewRasterFromImage(source)

    w := int(data[4]) + 1
    h := int(data[5]) + 1

    img := dest.Generator(w, h)

    if img != nil {
        return 1
    }
    return 0
}

func FuzzTextLayout(data []byte) int {
	if len(data) < 4 {
        return 0
    }

    x0 := float32(data[0])
    y0 := float32(data[1])
    
    for _, tt := range map[string]struct {
		text  string
		align fyne.TextAlign
		size  fyne.Size
	}{
		"short_leading_small": {
			text:  string(data[3:]),
			align: fyne.TextAlignLeading,
			size:  fyne.NewSize(x0, y0),
		},
		"short_center_small": {
			text:  string(data[3:]),
			align: fyne.TextAlignCenter,
			size:  fyne.NewSize(x0, y0),
		},
		"long_center_large": {
			text:  string(data[3:]),
			align: fyne.TextAlignCenter,
			size:  fyne.NewSize(x0, y0),
		},
		"long_trailing_large": {
			text:  string(data[3:]),
			align: fyne.TextAlignTrailing,
			size:  fyne.NewSize(x0, y0),
		},
	} {
		text := canvas.NewText(tt.text, theme.Color(theme.ColorNameForeground))
        text.Alignment = tt.align
        text.Resize(tt.size)
	}
    return 0
}

func FuzzLoadResourceFromURI(data []byte) int {
	tmp, err := WriteTempFile(data, "texturi")
    if err != nil {
        return 1
    }
    defer os.Remove(tmp.Name())

	uri := storage.NewFileURI(tmp.Name())
	_, err = storage.LoadResourceFromURI(uri)
    if err != nil {
        return 1
    }
    return 0
}
