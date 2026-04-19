package monitor

import (
	"testing"
	"time"
)

func TestSnapshotTrafficBucketSeconds(t *testing.T) {
	tests := []struct {
		name      string
		retention time.Duration
		want      int
	}{
		{name: "short window stays per-second", retention: 7 * time.Minute, want: 4},
		{name: "one hour window buckets", retention: time.Hour, want: 30},
		{name: "day window stays bounded", retention: 24 * time.Hour, want: 720},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := snapshotTrafficBucketSeconds(tt.retention); got != tt.want {
				t.Fatalf("snapshotTrafficBucketSeconds(%v) = %d, want %d", tt.retention, got, tt.want)
			}
		})
	}
}
