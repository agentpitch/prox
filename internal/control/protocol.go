// Package control defines the versioned, GUI-independent local agent protocol.
package control

import (
	"fmt"
	"reflect"
	"time"

	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/rules"
)

const ProtocolVersion = 1
const MaxConfigBytes = 8 << 20

type ConfigRequest struct {
	Config            config.Config `json:"config"`
	ExpectedUpdatedAt time.Time     `json:"expected_updated_at"`
	DryRun            bool          `json:"dry_run"`
	AllowDisruptive   bool          `json:"allow_disruptive"`
}

type ApplyPlan struct {
	Mode                 string   `json:"mode"`
	RuntimeRestart       bool     `json:"runtime_restart"`
	HTTPRebind           bool     `json:"http_rebind"`
	ConnectionsPreserved bool     `json:"connections_preserved"`
	ListeningAddress     string   `json:"listening_address"`
	Reasons              []string `json:"reasons"`
}

type ConfigResult struct {
	Config            config.Config `json:"config"`
	Plan              ApplyPlan     `json:"plan"`
	Applied           bool          `json:"applied"`
	PreviousUpdatedAt time.Time     `json:"previous_updated_at"`
}

type APIError struct {
	Code             string    `json:"code"`
	Message          string    `json:"message"`
	CurrentUpdatedAt time.Time `json:"current_updated_at,omitzero"`
}

func (e *APIError) Error() string { return e.Message }

type ErrorResponse struct {
	Error APIError `json:"error"`
}

type Status struct {
	ProtocolVersion  int       `json:"protocol_version"`
	Version          string    `json:"version"`
	PID              int       `json:"pid"`
	UpdatedAt        time.Time `json:"updated_at"`
	ListeningAddress string    `json:"listening_address"`
	ServicePaused    bool      `json:"service_paused"`
	WebUIEnabled     bool      `json:"webui_enabled"`
}

// ValidateConfig accepts the same rule language as the running router. Clone
// before canonicalization because normalization mutates slice elements.
func ValidateConfig(cfg config.Config) (config.Config, error) {
	canonical, err := config.Canonicalize(config.Clone(cfg))
	if err != nil {
		return config.Config{}, err
	}
	if _, err := rules.Compile(canonical, ""); err != nil {
		return config.Config{}, err
	}
	return canonical, nil
}

// PlanConfig is observational: it never binds a socket, writes configuration or
// starts interception. Callers serialize its snapshot with actual activation.
func PlanConfig(old, proposed config.Config, running bool) (config.Config, ApplyPlan, error) {
	cfg, err := ValidateConfig(proposed)
	if err != nil {
		return config.Config{}, ApplyPlan{}, err
	}
	plan := ApplyPlan{Mode: "hot_reload", ConnectionsPreserved: true, ListeningAddress: cfg.HTTP.Listen, Reasons: []string{}}
	oldComparable, newComparable := config.Clone(old), config.Clone(cfg)
	oldComparable.UpdatedAt, newComparable.UpdatedAt = time.Time{}, time.Time{}
	if reflect.DeepEqual(oldComparable, newComparable) {
		plan.Mode = "no_change"
		return cfg, plan, nil
	}
	oldEngine, err := rules.Compile(old, "")
	if err != nil {
		return config.Config{}, ApplyPlan{}, fmt.Errorf("current rules: %w", err)
	}
	newEngine, _ := rules.Compile(cfg, "") // ValidateConfig already checked it.
	if old.HTTP.Listen != cfg.HTTP.Listen {
		plan.HTTPRebind = true
		plan.Mode = "listener_rebind"
		plan.Reasons = append(plan.Reasons, "HTTP listener moves to a new address without restarting the process")
	}
	if running && RuntimeRestartRequired(old, cfg, !oldEngine.AllEnabledActionsDirect(), !newEngine.AllEnabledActionsDirect()) {
		plan.RuntimeRestart = true
		plan.ConnectionsPreserved = false
		plan.Mode = "runtime_restart"
		plan.Reasons = append(plan.Reasons, "Changing transparent listener/sniff settings or entering/leaving interception restarts the routing runtime and closes intercepted connections")
	} else {
		plan.Reasons = append(plan.Reasons, "New rules and proxy settings apply to new connections; existing connections keep their established route")
	}
	return cfg, plan, nil
}

func RuntimeRestartRequired(old, proposed config.Config, oldInterception, newInterception bool) bool {
	return oldInterception != newInterception || old.Transparent != proposed.Transparent
}
