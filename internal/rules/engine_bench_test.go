package rules

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/openai/pitchprox/internal/config"
)

func BenchmarkPreflightLargeRuleSetDefinitiveDirect(b *testing.B) {
	eng := benchmarkRulesEngine(b, 256)
	req := Request{
		PID:        100,
		AppPath:    `C:\Apps\browser.exe`,
		TargetIP:   netip.MustParseAddr("192.168.1.44"),
		TargetPort: 443,
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = eng.Preflight(req)
	}
}

func BenchmarkPreflightLargeRuleSetHostnameNeeded(b *testing.B) {
	eng := benchmarkRulesEngine(b, 256)
	req := Request{
		PID:        100,
		AppPath:    `C:\Apps\browser.exe`,
		TargetIP:   netip.MustParseAddr("140.82.121.4"),
		TargetPort: 443,
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = eng.Preflight(req)
	}
}

func benchmarkRulesEngine(b *testing.B, fillerRules int) *Engine {
	b.Helper()
	cfg := config.Config{Rules: make([]config.Rule, 0, fillerRules+3)}
	cfg.Rules = append(cfg.Rules, config.Rule{
		ID:           "local-direct",
		Name:         "Local direct",
		Enabled:      true,
		Applications: "*",
		TargetHosts:  "192.168.1.*",
		TargetPorts:  "443",
		Action:       config.ActionDirect,
	})
	cfg.Rules = append(cfg.Rules, config.Rule{
		ID:           "github-direct",
		Name:         "GitHub direct",
		Enabled:      true,
		Applications: "*",
		TargetHosts:  "github.com",
		TargetPorts:  "443",
		Action:       config.ActionDirect,
	})
	for i := 0; i < fillerRules; i++ {
		cfg.Rules = append(cfg.Rules, config.Rule{
			ID:           fmt.Sprintf("filler-%d", i),
			Name:         fmt.Sprintf("Filler %d", i),
			Enabled:      true,
			Applications: "helper.exe",
			TargetHosts:  "203.0.113.0/24",
			TargetPorts:  "8000-9000",
			Action:       config.ActionDirect,
		})
	}
	cfg.Rules = append(cfg.Rules, config.Rule{
		ID:           "default",
		Name:         "Default proxy",
		Enabled:      true,
		Applications: "*",
		TargetHosts:  "Any",
		TargetPorts:  "Any",
		Action:       config.ActionProxy,
		ProxyID:      "p1",
	})
	eng, err := Compile(cfg, "WORKSTATION")
	if err != nil {
		b.Fatal(err)
	}
	return eng
}
