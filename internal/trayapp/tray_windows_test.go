//go:build windows

package trayapp

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openai/pitchprox/internal/monitor"
)

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

func TestRemoteWebUIController(t *testing.T) {
	var enabled atomic.Bool
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
}
