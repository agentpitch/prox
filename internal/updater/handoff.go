package updater

import "time"

const (
	handoffPlanFormat    = "pitchprox.update-plan"
	updateHelperFileName = ".pitchProx-update-helper.exe"
)

type platformUpdateLock interface {
	Close() error
	ReleaseForHandoff() (released bool, err error)
}

type HandoffPlan struct {
	Format        string    `json:"format"`
	FormatVersion int       `json:"format_version"`
	Mode          string    `json:"mode"`
	ServiceName   string    `json:"service_name,omitempty"`
	TargetPath    string    `json:"target_path"`
	StagePath     string    `json:"stage_path"`
	BackupPath    string    `json:"backup_path"`
	RecoveryPath  string    `json:"recovery_path"`
	PlanPath      string    `json:"plan_path"`
	ReadyPath     string    `json:"ready_path"`
	ProceedPath   string    `json:"proceed_path"`
	StatePath     string    `json:"state_path"`
	ParentPID     int       `json:"parent_pid"`
	ParentStarted uint64    `json:"parent_started"`
	ListenAddress string    `json:"listen_address"`
	Version       string    `json:"version"`
	OldVersion    string    `json:"old_version"`
	OldSHA256     string    `json:"old_sha256"`
	NewSHA256     string    `json:"new_sha256"`
	UpdateToken   string    `json:"update_token"`
	TransactionID string    `json:"transaction_id"`
	LegacyHealth  bool      `json:"legacy_health"`
	CreatedAt     time.Time `json:"created_at"`
}
