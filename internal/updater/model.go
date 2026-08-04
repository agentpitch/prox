package updater

import "time"

const (
	PhaseIdle        = "idle"
	PhaseChecking    = "checking"
	PhaseDownloading = "downloading"
	PhaseVerifying   = "verifying"
	PhaseRestarting  = "restarting"
	PhaseSucceeded   = "completed"
	PhaseFailed      = "failed"
)

type Release struct {
	Version      string    `json:"version"`
	Name         string    `json:"name"`
	PublishedAt  time.Time `json:"published_at"`
	Prerelease   bool      `json:"prerelease"`
	PageURL      string    `json:"page_url"`
	Size         int64     `json:"size"`
	Installable  bool      `json:"installable"`
	Verification string    `json:"verification,omitempty"`
	Reason       string    `json:"reason,omitempty"`

	executable asset
	archive    asset
	checksums  asset
	manifest   asset
	id         int64
}

type CheckResult struct {
	CurrentVersion  string    `json:"current_version"`
	LatestVersion   string    `json:"latest_version,omitempty"`
	UpdateAvailable bool      `json:"update_available"`
	ComparisonKnown bool      `json:"comparison_known"`
	CheckedAt       time.Time `json:"checked_at"`
	Releases        []Release `json:"releases"`
}

type Status struct {
	Phase           string    `json:"phase"`
	Busy            bool      `json:"busy"`
	Version         string    `json:"version,omitempty"`
	TransactionID   string    `json:"transaction_id,omitempty"`
	Message         string    `json:"message,omitempty"`
	Error           string    `json:"error,omitempty"`
	DownloadedBytes int64     `json:"downloaded_bytes,omitempty"`
	TotalBytes      int64     `json:"total_bytes,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type asset struct {
	ID          int64
	Name        string
	APIURL      string
	Size        int64
	Digest      string
	State       string
	ContentType string
}
