package config

import (
	"strings"
	"testing"
)

func testValidConfig() Config {
	return Config{
		HTTP:        HTTPConfig{Listen: "127.0.0.1:18080"},
		Transparent: TransparentConfig{ListenerPort: 26001, SniffBytes: 4096, SniffTimeout: 1500},
		Proxies: []ProxyProfile{{
			ID:      "p1",
			Name:    "Primary",
			Type:    "http",
			Address: "127.0.0.1:8080",
			Enabled: true,
		}},
		Chains: []ProxyChain{{
			ID:       "c1",
			Name:     "Main chain",
			ProxyIDs: []string{"p1"},
			Enabled:  true,
		}},
		Rules: []Rule{{
			ID:           "r1",
			Name:         "Default proxy",
			Enabled:      true,
			Applications: "*",
			TargetHosts:  "Any",
			TargetPorts:  "443",
			Action:       ActionProxy,
			ProxyID:      "p1",
		}},
	}
}

func TestNormalizeClearsUnusedRouteTargets(t *testing.T) {
	cfg := Config{
		HTTP:        HTTPConfig{Listen: " 127.0.0.1:18080 "},
		Transparent: TransparentConfig{ListenerPort: 26001, SniffBytes: 4096, SniffTimeout: 1500},
		Proxies:     []ProxyProfile{{ID: " p1 ", Type: "HTTP CONNECT", Address: " host:8080 "}},
		Chains:      []ProxyChain{{ID: " c1 ", ProxyIDs: []string{" p1 "}}},
		Rules: []Rule{{
			ID:      " r1 ",
			Action:  ActionDirect,
			ProxyID: " p1 ",
			ChainID: " c1 ",
		}},
	}
	Normalize(&cfg)
	if cfg.HTTP.Listen != "127.0.0.1:18080" {
		t.Fatalf("unexpected listen: %q", cfg.HTTP.Listen)
	}
	if cfg.Proxies[0].ID != "p1" || cfg.Proxies[0].Type != "http" || cfg.Proxies[0].Address != "host:8080" {
		t.Fatalf("proxy not normalized: %+v", cfg.Proxies[0])
	}
	if cfg.Chains[0].ID != "c1" || cfg.Chains[0].ProxyIDs[0] != "p1" {
		t.Fatalf("chain not normalized: %+v", cfg.Chains[0])
	}
	if cfg.Rules[0].ID != "r1" {
		t.Fatalf("rule id not normalized: %+v", cfg.Rules[0])
	}
	if cfg.Rules[0].ProxyID != "" || cfg.Rules[0].ChainID != "" {
		t.Fatalf("direct rule retained route targets: %+v", cfg.Rules[0])
	}
}

func TestNormalizeCanonicalizesProxyAndChainActions(t *testing.T) {
	cfg := Config{
		HTTP:        HTTPConfig{Listen: "127.0.0.1:18080"},
		Transparent: TransparentConfig{ListenerPort: 26001, SniffBytes: 4096, SniffTimeout: 1500},
		Rules:       []Rule{{ID: "r1", Action: RuleAction("CHAIN"), ProxyID: "p1", ChainID: " c1 "}},
	}
	Normalize(&cfg)
	if cfg.Rules[0].Action != ActionChain {
		t.Fatalf("expected chain action, got %q", cfg.Rules[0].Action)
	}
	if cfg.Rules[0].ProxyID != "" || cfg.Rules[0].ChainID != "c1" {
		t.Fatalf("unexpected route targets after normalize: %+v", cfg.Rules[0])
	}
}

func TestNormalizePreservesUnsupportedActionForValidation(t *testing.T) {
	cfg := testValidConfig()
	cfg.Rules[0].Action = RuleAction("PrOxYy")
	Normalize(&cfg)
	if cfg.Rules[0].Action != RuleAction("proxyy") {
		t.Fatalf("unsupported action was rewritten unexpectedly: %+v", cfg.Rules[0])
	}
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "unsupported action") {
		t.Fatalf("expected unsupported action validation error, got %v", err)
	}
}

func TestValidateEnabledRuleRequiresEnabledProxy(t *testing.T) {
	cfg := testValidConfig()
	cfg.Proxies[0].Enabled = false
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "disabled proxy") {
		t.Fatalf("expected disabled proxy validation error, got %v", err)
	}
}

func TestValidateEnabledChainMustContainEnabledProxy(t *testing.T) {
	cfg := testValidConfig()
	cfg.Rules[0] = Rule{ID: "r1", Name: "Chain rule", Enabled: true, Applications: "*", TargetHosts: "Any", TargetPorts: "443", Action: ActionChain, ChainID: "c1"}
	cfg.Proxies[0].Enabled = false
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "enabled chain") {
		t.Fatalf("expected enabled chain validation error, got %v", err)
	}
}

func TestValidateEnabledChainCannotBeEmpty(t *testing.T) {
	cfg := testValidConfig()
	cfg.Chains[0].ProxyIDs = nil
	cfg.Rules[0] = Rule{ID: "r1", Name: "Chain rule", Enabled: true, Applications: "*", TargetHosts: "Any", TargetPorts: "443", Action: ActionChain, ChainID: "c1"}
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "must contain at least one proxy") {
		t.Fatalf("expected empty chain validation error, got %v", err)
	}
}
