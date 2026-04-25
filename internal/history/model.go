package history

import (
	"time"

	"github.com/openai/pitchprox/internal/config"
)

type ConnectionRecord struct {
	ID            string
	PID           uint32
	ExePath       string
	SourceIP      string
	SourcePort    uint16
	OriginalIP    string
	OriginalPort  uint16
	Hostname      string
	RuleID        string
	RuleName      string
	Action        config.RuleAction
	ProxyID       string
	ChainID       string
	State         string
	BytesUp       int64
	BytesDown     int64
	CreatedAt     time.Time
	LastUpdatedAt time.Time
	Count         int64
}

type LogRecord struct {
	Time         time.Time
	Level        string
	Message      string
	ConnectionID string
	PID          uint32
	ExePath      string
	Action       config.RuleAction
	RuleID       string
	RuleName     string
	Host         string
	Port         uint16
}

type TrafficSample struct {
	Time      time.Time
	UpBytes   int64
	DownBytes int64
}

type TrafficTotals struct {
	UpBytes   int64
	DownBytes int64
}

type RuleActivity struct {
	RuleID      string
	RuleName    string
	Action      config.RuleAction
	Connections int64
	UpBytes     int64
	DownBytes   int64
}

type SnapshotData struct {
	Connections   []ConnectionRecord
	Logs          []LogRecord
	Traffic       []TrafficSample
	TrafficTotals TrafficTotals
	RuleStats     []RuleActivity
}

type NewConnectionOptions struct {
	Baseline time.Duration
	Recent   time.Duration
	Limit    int
	Live     []ConnectionRecord
}
