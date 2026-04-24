//go:build windows

package trayapp

import (
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
