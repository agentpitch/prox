package config

import (
	"fmt"
	"strings"
	"time"
)

type RuleAction string

const (
	ActionDirect RuleAction = "direct"
	ActionProxy  RuleAction = "proxy"
	ActionChain  RuleAction = "chain"
	ActionBlock  RuleAction = "block"
)

type Config struct {
	Version          int               `json:"version"`
	UpdatedAt        time.Time         `json:"updated_at"`
	RetentionMinutes int               `json:"retention_minutes"`
	HTTP             HTTPConfig        `json:"http"`
	Transparent      TransparentConfig `json:"transparent"`
	Proxies          []ProxyProfile    `json:"proxies"`
	Chains           []ProxyChain      `json:"chains"`
	Rules            []Rule            `json:"rules"`
}

type HTTPConfig struct {
	Listen string `json:"listen"`
}

type TransparentConfig struct {
	IPv4Listener string `json:"ipv4_listener"`
	IPv6Listener string `json:"ipv6_listener"`
	ListenerPort int    `json:"listener_port"`
	SniffBytes   int    `json:"sniff_bytes"`
	SniffTimeout int    `json:"sniff_timeout_ms"`
}

type ProxyProfile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Address  string `json:"address"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Enabled  bool   `json:"enabled"`
}

type ProxyChain struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	ProxyIDs []string `json:"proxy_ids"`
	Enabled  bool     `json:"enabled"`
}

type Rule struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Enabled      bool       `json:"enabled"`
	Applications string     `json:"applications"`
	TargetHosts  string     `json:"target_hosts"`
	TargetPorts  string     `json:"target_ports"`
	Action       RuleAction `json:"action"`
	ProxyID      string     `json:"proxy_id,omitempty"`
	ChainID      string     `json:"chain_id,omitempty"`
	Notes        string     `json:"notes,omitempty"`
}

func DefaultConfig() Config {
	return Config{
		Version:          1,
		UpdatedAt:        time.Now().UTC(),
		RetentionMinutes: 7,
		HTTP: HTTPConfig{
			Listen: "127.0.0.1:18080",
		},
		Transparent: TransparentConfig{
			IPv4Listener: "0.0.0.0",
			IPv6Listener: "::",
			ListenerPort: 26001,
			SniffBytes:   4096,
			SniffTimeout: 1500,
		},
		Rules: []Rule{
			{
				ID:           "localhost",
				Name:         "Localhost / This PC",
				Enabled:      true,
				Applications: "*",
				TargetHosts:  "localhost; 127.0.0.1; ::1; %ComputerName%",
				TargetPorts:  "Any",
				Action:       ActionDirect,
				Notes:        "Bypass loopback and this machine.",
			},
			{
				ID:           "default",
				Name:         "Default",
				Enabled:      true,
				Applications: "*",
				TargetHosts:  "Any",
				TargetPorts:  "Any",
				Action:       ActionDirect,
			},
		},
	}
}

func Normalize(cfg *Config) {
	if cfg == nil {
		return
	}
	if cfg.Version == 0 {
		cfg.Version = 1
	}
	if cfg.RetentionMinutes <= 0 {
		cfg.RetentionMinutes = 7
	}
	cfg.HTTP.Listen = strings.TrimSpace(cfg.HTTP.Listen)
	cfg.Transparent.IPv4Listener = strings.TrimSpace(cfg.Transparent.IPv4Listener)
	cfg.Transparent.IPv6Listener = strings.TrimSpace(cfg.Transparent.IPv6Listener)

	for i := range cfg.Proxies {
		cfg.Proxies[i].ID = strings.TrimSpace(cfg.Proxies[i].ID)
		cfg.Proxies[i].Name = strings.TrimSpace(cfg.Proxies[i].Name)
		cfg.Proxies[i].Type = normalizeProxyType(cfg.Proxies[i].Type)
		cfg.Proxies[i].Address = strings.TrimSpace(cfg.Proxies[i].Address)
		cfg.Proxies[i].Username = strings.TrimSpace(cfg.Proxies[i].Username)
	}
	for i := range cfg.Chains {
		cfg.Chains[i].ID = strings.TrimSpace(cfg.Chains[i].ID)
		cfg.Chains[i].Name = strings.TrimSpace(cfg.Chains[i].Name)
		for j := range cfg.Chains[i].ProxyIDs {
			cfg.Chains[i].ProxyIDs[j] = strings.TrimSpace(cfg.Chains[i].ProxyIDs[j])
		}
	}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		r.ID = strings.TrimSpace(r.ID)
		r.Name = strings.TrimSpace(r.Name)
		r.Applications = strings.TrimSpace(r.Applications)
		r.TargetHosts = strings.TrimSpace(r.TargetHosts)
		r.TargetPorts = strings.TrimSpace(r.TargetPorts)
		r.ProxyID = strings.TrimSpace(r.ProxyID)
		r.ChainID = strings.TrimSpace(r.ChainID)
		r.Notes = strings.TrimSpace(r.Notes)
		r.Action = normalizeAction(r.Action)
		switch r.Action {
		case ActionProxy:
			r.ChainID = ""
		case ActionChain:
			r.ProxyID = ""
		default:
			r.ProxyID = ""
			r.ChainID = ""
		}
	}
}

func normalizeProxyType(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "http", "http connect", "http_connect", "connect", "":
		return "http"
	case "socks", "socks5", "socks v5":
		return "socks5"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func normalizeAction(v RuleAction) RuleAction {
	switch strings.ToLower(strings.TrimSpace(string(v))) {
	case string(ActionProxy):
		return ActionProxy
	case string(ActionChain):
		return ActionChain
	case string(ActionBlock):
		return ActionBlock
	default:
		return ActionDirect
	}
}

func Validate(cfg Config) error {
	Normalize(&cfg)
	if cfg.HTTP.Listen == "" {
		return fmt.Errorf("http.listen is required")
	}
	if cfg.Transparent.ListenerPort < 1 || cfg.Transparent.ListenerPort > 65535 {
		return fmt.Errorf("transparent.listener_port must be in 1..65535")
	}
	if cfg.RetentionMinutes < 1 || cfg.RetentionMinutes > 1440 {
		return fmt.Errorf("retention_minutes must be in 1..1440")
	}
	seenProxy := map[string]struct{}{}
	for _, p := range cfg.Proxies {
		if p.ID == "" {
			return fmt.Errorf("proxy id is required")
		}
		if _, ok := seenProxy[p.ID]; ok {
			return fmt.Errorf("duplicate proxy id %q", p.ID)
		}
		seenProxy[p.ID] = struct{}{}
		switch p.Type {
		case "http", "socks5":
		default:
			return fmt.Errorf("proxy %q has unsupported type %q", p.Name, p.Type)
		}
		if p.Address == "" {
			return fmt.Errorf("proxy %q address is required", p.Name)
		}
	}
	seenChain := map[string]struct{}{}
	for _, c := range cfg.Chains {
		if c.ID == "" {
			return fmt.Errorf("chain id is required")
		}
		if _, ok := seenChain[c.ID]; ok {
			return fmt.Errorf("duplicate chain id %q", c.ID)
		}
		seenChain[c.ID] = struct{}{}
		for _, id := range c.ProxyIDs {
			if _, ok := seenProxy[id]; !ok {
				return fmt.Errorf("chain %q references unknown proxy %q", c.Name, id)
			}
		}
	}
	seenRule := map[string]struct{}{}
	for _, r := range cfg.Rules {
		if r.ID == "" {
			return fmt.Errorf("rule id is required")
		}
		if _, ok := seenRule[r.ID]; ok {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seenRule[r.ID] = struct{}{}
		switch r.Action {
		case ActionDirect, ActionProxy, ActionChain, ActionBlock:
		default:
			return fmt.Errorf("rule %q has unsupported action %q", r.Name, r.Action)
		}
		if r.Action == ActionProxy && r.ProxyID == "" {
			return fmt.Errorf("rule %q uses action=proxy but proxy_id is empty", r.Name)
		}
		if r.Action == ActionChain && r.ChainID == "" {
			return fmt.Errorf("rule %q uses action=chain but chain_id is empty", r.Name)
		}
	}
	return nil
}
