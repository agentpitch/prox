//go:build windows

package trayapp

import (
	"encoding/binary"
	"image"
	"image/color"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openai/pitchprox/internal/monitor"
)

func TestEncodeICOUsesUncompressedDIB(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	img.SetNRGBA(0, 15, color.NRGBA{R: 11, G: 22, B: 33, A: 44})

	data, err := encodeICO(img)
	if err != nil {
		t.Fatalf("encodeICO: %v", err)
	}
	const (
		iconHeader = 6 + 16
		dibHeader  = 40
		xorBytes   = 16 * 16 * 4
		maskBytes  = 16 * 4
		wantLen    = iconHeader + dibHeader + xorBytes + maskBytes
	)
	if len(data) != wantLen {
		t.Fatalf("ico len = %d, want %d", len(data), wantLen)
	}
	if got := binary.LittleEndian.Uint16(data[2:4]); got != 1 {
		t.Fatalf("icon type = %d, want 1", got)
	}
	if got := binary.LittleEndian.Uint32(data[14:18]); got != dibHeader+xorBytes+maskBytes {
		t.Fatalf("image bytes = %d, want %d", got, dibHeader+xorBytes+maskBytes)
	}
	if got := binary.LittleEndian.Uint32(data[22:26]); got != dibHeader {
		t.Fatalf("DIB header size = %d, want %d", got, dibHeader)
	}
	if got := binary.LittleEndian.Uint32(data[30:34]); got != 32 {
		t.Fatalf("DIB height = %d, want 32", got)
	}
	firstPixel := data[iconHeader+dibHeader : iconHeader+dibHeader+4]
	if got := [4]byte{firstPixel[0], firstPixel[1], firstPixel[2], firstPixel[3]}; got != [4]byte{33, 22, 11, 44} {
		t.Fatalf("first BGRA pixel = %v, want [33 22 11 44]", got)
	}
}

func TestTrafficSeriesUsesFixedWindowWithoutMapGrowth(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	history, rx, tx, peakRx, peakTx := trafficSeries([]monitor.TrafficSample{
		{Time: now.Add(-2 * time.Second), UpBytes: 10, DownBytes: 20},
		{Time: now.Add(-2 * time.Second), UpBytes: 5, DownBytes: 7},
		{Time: now, UpBytes: 3, DownBytes: 4},
		{Time: now.Add(-time.Duration(trayHistorySeconds+1) * time.Second), UpBytes: 1000, DownBytes: 1000},
	})

	if got := len(history); got != trayHistorySeconds {
		t.Fatalf("history len = %d, want %d", got, trayHistorySeconds)
	}
	bucket := history[len(history)-3]
	if bucket.TxBytes != 15 || bucket.RxBytes != 27 {
		t.Fatalf("aggregated bucket = tx=%d rx=%d, want tx=15 rx=27", bucket.TxBytes, bucket.RxBytes)
	}
	if tx != 3 || rx != 4 {
		t.Fatalf("current = tx=%d rx=%d, want tx=3 rx=4", tx, rx)
	}
	if peakTx != 15 || peakRx != 27 {
		t.Fatalf("peaks = tx=%d rx=%d, want tx=15 rx=27", peakTx, peakRx)
	}
}

func TestTrafficIconFrameUsesHighContrastPixels(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	drawTrafficIconFrame(img)

	if got := img.NRGBAAt(0, 0); got.A < 200 || got.R < 220 {
		t.Fatalf("border pixel = %#v, want bright opaque border", got)
	}
	if got := img.NRGBAAt(8, 8); got.A < 230 || got.R > 40 || got.G > 60 || got.B < 30 {
		t.Fatalf("background pixel = %#v, want dark opaque background", got)
	}
}

func TestRemoteWebUIController(t *testing.T) {
	var enabled atomic.Bool
	var paused atomic.Bool
	enabled.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/control/webui/status":
			w.Header().Set("Content-Type", "application/json")
			if enabled.Load() {
				_, _ = w.Write([]byte(`{"enabled":true}`))
			} else {
				_, _ = w.Write([]byte(`{"enabled":false}`))
			}
		case "/api/control/webui/enable":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			enabled.Store(true)
			_, _ = w.Write([]byte(`{"enabled":true}`))
		case "/api/control/webui/disable":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			enabled.Store(false)
			_, _ = w.Write([]byte(`{"enabled":false}`))
		case "/api/control/service/status":
			w.Header().Set("Content-Type", "application/json")
			if paused.Load() {
				_, _ = w.Write([]byte(`{"paused":true,"webui_enabled":false}`))
			} else {
				_, _ = w.Write([]byte(`{"paused":false,"webui_enabled":true}`))
			}
		case "/api/control/service/pause":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			paused.Store(true)
			enabled.Store(false)
			_, _ = w.Write([]byte(`{"paused":true,"webui_enabled":false}`))
		case "/api/control/service/resume":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			paused.Store(false)
			enabled.Store(true)
			_, _ = w.Write([]byte(`{"paused":false,"webui_enabled":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	controller := remoteWebUIController{url: server.URL}
	if !controller.WebUIRunning() {
		t.Fatal("WebUIRunning = false, want true")
	}
	if err := controller.DisableWebUI(); err != nil {
		t.Fatalf("DisableWebUI: %v", err)
	}
	if controller.WebUIRunning() {
		t.Fatal("WebUIRunning = true after disable")
	}
	if err := controller.EnableWebUI(); err != nil {
		t.Fatalf("EnableWebUI: %v", err)
	}
	if !controller.WebUIRunning() {
		t.Fatal("WebUIRunning = false after enable")
	}
	if controller.ServicePaused() {
		t.Fatal("ServicePaused = true before pause")
	}
	if err := controller.PauseService(); err != nil {
		t.Fatalf("PauseService: %v", err)
	}
	if !controller.ServicePaused() {
		t.Fatal("ServicePaused = false after pause")
	}
	if err := controller.ResumeService(); err != nil {
		t.Fatalf("ResumeService: %v", err)
	}
	if controller.ServicePaused() {
		t.Fatal("ServicePaused = true after resume")
	}
}
