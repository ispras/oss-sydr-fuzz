package fuzz

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"image"
	"io/ioutil"
	"net/url"
	"os"
	"time"

	"fyne.io/fyne/v2/test"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
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

func RandFileName(ext string) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	hash := hex.EncodeToString(b)
	return fmt.Sprintf("fuzz-%s.%s", hash, ext)
}

func FuzzNewImageFromFile(data []byte) int {
	if len(data) < 4 {
		return 0
	}

	_, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return 1
	}

	res := fyne.NewStaticResource(RandFileName("img"), data)
	img := canvas.NewImageFromResource(res)

	if img != nil {
		img.FillMode = canvas.ImageFillContain
		img.Resize(fyne.NewSize(64, 64))

		if raster := canvas.NewRasterFromImage(img.Image); raster != nil {
			_ = raster.Generator(32, 32)
		}
	}

	app := test.NewApp()
	win := test.NewWindow(img)
	win.Resize(fyne.NewSize(200, 200))
	win.Close()
	app.Quit()
	return 0
}

func FuzzSVGBytes(data []byte) int {
	if len(data) < 4 {
		return 0
	}
	res := fyne.NewStaticResource(RandFileName("svg"), data)
	svg := canvas.NewImageFromResource(res)
	if svg != nil {
		svg.Resize(fyne.NewSize(128, 128))
	}
	app := test.NewApp()
	win := test.NewWindow(svg)
	win.Resize(fyne.NewSize(200, 200))
	win.Close()
	app.Quit()
	return 0
}

func FuzzMarkdown(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	md := string(data)
	rt := widget.NewRichTextFromMarkdown(md)
	app := test.NewApp()
	win := test.NewWindow(rt)
	win.Resize(fyne.NewSize(300, 200))
	win.Close()
	app.Quit()
	return 0
}

func FuzzURI(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	s := string(data)
	_, err := url.ParseRequestURI(s)
	if err == nil {
		_, _ = storage.ParseURI(s)
	}
	return 0
}

func FuzzEntryText(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	text := string(data)
	e := widget.NewEntry()
	e.SetText(text)
	e.TypedRune('a')
	e.TypedShortcut(&fyne.ShortcutCut{})
	app := test.NewApp()
	win := test.NewWindow(e)
	win.Resize(fyne.NewSize(200, 100))
	win.Close()
	app.Quit()
	return 0
}

func FuzzExerciseImageFile(data []byte) int {
	tmp, err := WriteTempFile(data, "fynefile")
	if err != nil {
		return 1
	}
	defer os.Remove(tmp.Name())

	path := tmp.Name()

	img := canvas.NewImageFromFile(path)

	modes := []canvas.ImageFill{
		canvas.ImageFillContain,
		canvas.ImageFillStretch,
		canvas.ImageFillOriginal,
	}
	for _, m := range modes {
		img.FillMode = m
		img.Refresh()
	}

	img.Resize(fyne.NewSize(10, 10))
	img.Refresh()

	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		if decoded, _, derr := image.Decode(f); derr == nil {
			img.Image = decoded
			img.Refresh()

			if raster := canvas.NewRasterFromImage(decoded); raster != nil {
				_ = raster.Generator(128, 128)
			}
		}
	}

	app := test.NewApp()
	defer test.NewApp().Quit()

	win := test.NewWindow(img)
	win.Resize(fyne.NewSize(200, 200))

	time.Sleep(50 * time.Millisecond)

	win.Resize(fyne.NewSize(400, 300))
	img.Resize(fyne.NewSize(300, 200))
	img.Refresh()
	canvas.Refresh(img)
	time.Sleep(10 * time.Millisecond)

	win.Close()
	app.Quit()
	return 0
}
