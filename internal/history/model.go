package history

import (
	"time"

	"github.com/agentpitch/prox/internal/config"
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

type DroppedRecord struct {
	DropID     string
	DroppedAt  time.Time
	Connection ConnectionRecord
}

type DroppedQuery struct {
	Search string
	Offset int
	Limit  int
}

type DroppedResult struct {
	Items     []DroppedRecord
	Total     int
	Offset    int
	Limit     int
	MaxBytes  int64
	FileBytes int64
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
	RuleID               string
	RuleName             string
	Action               config.RuleAction
	Connections          int64
	UpBytes              int64
	DownBytes            int64
	ConditionApplication string `json:"condition_application,omitempty"`
	ConditionHost        string `json:"condition_host,omitempty"`
	ConditionPort        string `json:"condition_port,omitempty"`
	ConditionSource      string `json:"condition_source,omitempty"`
	ConditionOverflow    bool   `json:"condition_overflow,omitempty"`
}

type RuleActivityBucket struct {
	Time        time.Time
	Connections int64
	UpBytes     int64
	DownBytes   int64
}

type RuleActivitySeries struct {
	RuleID      string
	RuleName    string
	Action      config.RuleAction
	Connections int64
	UpBytes     int64
	DownBytes   int64
	Buckets     []RuleActivityBucket
}

type RuleActivityTimeline struct {
	GeneratedAt   time.Time
	WindowMinutes int
	BucketSeconds float64
	Points        int
	Series        []RuleActivitySeries
}

type RuleConditionSources struct {
	Intercepted    int64 `json:"intercepted"`
	DirectObserver int64 `json:"direct_observer"`
}

type RuleConditionActivity struct {
	Application string               `json:"application"`
	Host        string               `json:"host"`
	Port        string               `json:"port"`
	Hits        int64                `json:"hits"`
	Share       float64              `json:"share"`
	LastSeen    time.Time            `json:"last_seen"`
	Sources     RuleConditionSources `json:"sources"`
}

type RuleConditionDimensionValue struct {
	Value    string               `json:"value"`
	Hits     int64                `json:"hits"`
	Share    float64              `json:"share"`
	LastSeen time.Time            `json:"last_seen"`
	Sources  RuleConditionSources `json:"sources"`
}

type RuleConditionDimension struct {
	TotalHits int64                         `json:"total_hits"`
	OtherHits int64                         `json:"other_hits"`
	Truncated bool                          `json:"truncated"`
	Values    []RuleConditionDimensionValue `json:"values"`
}

type RuleConditionDimensions struct {
	Applications RuleConditionDimension `json:"applications"`
	Hosts        RuleConditionDimension `json:"hosts"`
	Ports        RuleConditionDimension `json:"ports"`
}

type RuleConditionActivityResult struct {
	GeneratedAt      time.Time               `json:"generated_at"`
	RuleID           string                  `json:"rule_id"`
	WindowMinutes    int                     `json:"window_minutes"`
	TotalHits        int64                   `json:"total_hits"`
	OtherHits        int64                   `json:"other_hits"`
	UnattributedHits int64                   `json:"unattributed_hits"`
	Truncated        bool                    `json:"truncated"`
	SourceHits       RuleConditionSources    `json:"source_hits"`
	Conditions       []RuleConditionActivity `json:"conditions"`
	Dimensions       RuleConditionDimensions `json:"dimensions"`
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
