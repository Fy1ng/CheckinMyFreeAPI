package desktop

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"sync"
)

var appIcon = sync.OnceValue(func() []byte {
	canvas := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	ink := color.NRGBA{R: 20, G: 43, B: 40, A: 255}
	paper := color.NRGBA{R: 245, G: 250, B: 247, A: 255}
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			dx, dy := 0, 0
			if x < 12 {
				dx = 12 - x
			} else if x > 51 {
				dx = x - 51
			}
			if y < 12 {
				dy = 12 - y
			} else if y > 51 {
				dy = y - 51
			}
			if dx*dx+dy*dy <= 144 {
				canvas.SetNRGBA(x, y, ink)
			}
		}
	}
	polygon := [][2]float64{{17, 47}, {17, 17}, {24, 17}, {41, 38}, {41, 17}, {48, 17}, {48, 47}, {41, 47}, {24, 26}, {24, 47}}
	for y := 16; y < 49; y++ {
		for x := 16; x < 49; x++ {
			inside := false
			px, py := float64(x)+0.5, float64(y)+0.5
			for i, j := 0, len(polygon)-1; i < len(polygon); j, i = i, i+1 {
				a, b := polygon[i], polygon[j]
				if (a[1] > py) != (b[1] > py) && px < (b[0]-a[0])*(py-a[1])/(b[1]-a[1])+a[0] {
					inside = !inside
				}
			}
			if inside {
				canvas.SetNRGBA(x, y, paper)
			}
		}
	}
	var out bytes.Buffer
	_ = png.Encode(&out, canvas)
	return out.Bytes()
})
