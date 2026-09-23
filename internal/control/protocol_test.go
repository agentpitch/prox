package control

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/agentpitch/prox/internal/config"
)

func TestStrictConfigJSON(t *testing.T) {
	for _, input := range []string{
		`{"rules":[{"id":"x","enabled":null}]}`,
		`{"retention_minutes":null}`,
		`{"http":null}`,
		`{"rules":[null]}`,
		`{"rules":[],"rules":[]}`,
		`{"Rules":[]}`,
		`{"updated_at":null}`,
		`{"http":{"listen":"127.0.0.1:18080","listen":"127.0.0.1:8080"}}`,
		`{} {}`,
		`{"unexpected":true}`,
		"{\"rules\":[{\"id\":\"bad\xffencoding\"}]}",
	} {
		var cfg config.Config
		if err := DecodeJSON([]byte(input), &cfg); err == nil {
			t.Errorf("accepted ambiguous input: %s", input)
		}
	}
	data, _ := json.Marshal(config.DefaultConfig())
	var decoded config.Config
	if err := DecodeJSON(append([]byte{0xef, 0xbb, 0xbf}, data...), &decoded); err != nil {
		t.Fatalf("exported config with BOM/nil collections: %v", err)
	}
}

func TestPlanClassifiesChangesWithoutMutatingInput(t *testing.T) {
	old, err := ValidateConfig(config.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, mode               string
		mutate                   func(*config.Config)
		running, restart, rebind bool
	}{
		{"same", "no_change", func(c *config.Config) { c.UpdatedAt = time.Time{} }, true, false, false},
		{"rules", "hot_reload", func(c *config.Config) { c.Rules[0].Name = "Renamed" }, true, false, false},
		{"proxy mode", "runtime_restart", func(c *config.Config) { c.Rules[0].Action = config.ActionBlock }, true, true, false},
		{"sniff", "runtime_restart", func(c *config.Config) { c.Transparent.SniffBytes++ }, true, true, false},
		{"HTTP", "listener_rebind", func(c *config.Config) { c.HTTP.Listen = "127.0.0.1:19090" }, true, false, true},
		{"paused", "hot_reload", func(c *config.Config) { c.Rules[0].Action = config.ActionBlock }, false, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			proposed := config.Clone(old)
			test.mutate(&proposed)
			before, _ := json.Marshal(proposed)
			_, plan, err := PlanConfig(old, proposed, test.running)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Mode != test.mode || plan.RuntimeRestart != test.restart || plan.HTTPRebind != test.rebind || plan.ConnectionsPreserved == test.restart {
				t.Fatalf("unexpected plan: %+v", plan)
			}
			after, _ := json.Marshal(proposed)
			if string(before) != string(after) {
				t.Fatal("planning mutated proposed config")
			}
		})
	}
}
