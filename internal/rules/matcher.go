package rules

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/openai/pitchprox/internal/config"
)

type CompiledRule struct {
	Rule                config.Rule
	apps                []appPattern
	appsAny             bool
	hosts               []hostPattern
	hostsAny            bool
	ports               []portRange
	portsAny            bool
	hostnameDependent   bool
	hasIPHostConstraint bool
}

type Engine struct {
	rules            []CompiledRule
	computerName     string
	allEnabledDirect bool
}

type Request struct {
	PID        uint32
	AppPath    string
	Hostname   string
	TargetIP   netip.Addr
	TargetPort uint16
}

type Decision struct {
	Matched bool
	RuleID  string
	Rule    string
	Action  config.RuleAction
	ProxyID string
	ChainID string
}

type PreflightResult struct {
	Decision
	Definitive    bool
	NeedsHostname bool
}

func Compile(cfg config.Config, computerName string) (*Engine, error) {
	eng := &Engine{computerName: strings.ToLower(strings.TrimSpace(computerName)), allEnabledDirect: true}
	for _, r := range cfg.Rules {
		cr := CompiledRule{Rule: r}
		var err error
		cr.apps, cr.appsAny, err = parseApplications(r.Applications)
		if err != nil {
			return nil, fmt.Errorf("rule %q applications: %w", r.Name, err)
		}
		cr.hosts, cr.hostsAny, err = parseHosts(r.TargetHosts)
		if err != nil {
			return nil, fmt.Errorf("rule %q target hosts: %w", r.Name, err)
		}
		cr.ports, cr.portsAny, err = parsePorts(r.TargetPorts)
		if err != nil {
			return nil, fmt.Errorf("rule %q target ports: %w", r.Name, err)
		}
		for _, hp := range cr.hosts {
			switch hp.kind {
			case hostExactName, hostGlobName, hostComputerName:
				cr.hostnameDependent = true
			case hostExactIP, hostCIDR, hostIPRange, hostGlobIP:
				cr.hasIPHostConstraint = true
			}
		}
		if r.Enabled && r.Action != config.ActionDirect {
			eng.allEnabledDirect = false
		}
		eng.rules = append(eng.rules, cr)
	}
	return eng, nil
}

func (e *Engine) AllEnabledActionsDirect() bool {
	return e.allEnabledDirect
}

func (e *Engine) Match(req Request) Decision {
	for _, r := range e.rules {
		if !r.Rule.Enabled {
			continue
		}
		if !r.matchApp(req.AppPath, req.PID) {
			continue
		}
		if !r.matchHost(req.Hostname, req.TargetIP, e.computerName) {
			continue
		}
		if !r.matchPort(req.TargetPort) {
			continue
		}
		return Decision{
			Matched: true,
			RuleID:  r.Rule.ID,
			Rule:    r.Rule.Name,
			Action:  r.Rule.Action,
			ProxyID: r.Rule.ProxyID,
			ChainID: r.Rule.ChainID,
		}
	}
	return Decision{Action: config.ActionDirect}
}

func (e *Engine) Preflight(req Request) PreflightResult {
	for i, r := range e.rules {
		if !r.Rule.Enabled {
			continue
		}
		if !r.matchApp(req.AppPath, req.PID) {
			continue
		}
		if !r.matchPort(req.TargetPort) {
			continue
		}
		hostState := r.preflightHost(req.Hostname, req.TargetIP, e.computerName)
		switch hostState {
		case hostPreflightMatch:
			return PreflightResult{
				Decision: Decision{
					Matched: true,
					RuleID:  r.Rule.ID,
					Rule:    r.Rule.Name,
					Action:  r.Rule.Action,
					ProxyID: r.Rule.ProxyID,
					ChainID: r.Rule.ChainID,
				},
				Definitive: true,
			}
		case hostPreflightNeedHostname:
			if r.Rule.Action == config.ActionDirect {
				if dec, ok := e.definitiveDirectWithoutHostname(req, i+1); ok {
					return PreflightResult{
						Decision:   dec,
						Definitive: true,
					}
				}
			}
			return PreflightResult{
				Decision: Decision{
					Matched: true,
					RuleID:  r.Rule.ID,
					Rule:    r.Rule.Name,
					Action:  r.Rule.Action,
					ProxyID: r.Rule.ProxyID,
					ChainID: r.Rule.ChainID,
				},
				NeedsHostname: true,
			}
		case hostPreflightNoMatch:
			continue
		}
	}
	return PreflightResult{Decision: Decision{Action: config.ActionDirect}, Definitive: true}
}

func (e *Engine) definitiveDirectWithoutHostname(req Request, start int) (Decision, bool) {
	for _, r := range e.rules[start:] {
		if !r.Rule.Enabled {
			continue
		}
		if !r.matchApp(req.AppPath, req.PID) {
			continue
		}
		if !r.matchPort(req.TargetPort) {
			continue
		}
		hostState := r.preflightHost(req.Hostname, req.TargetIP, e.computerName)
		switch hostState {
		case hostPreflightMatch:
			if r.Rule.Action != config.ActionDirect {
				return Decision{}, false
			}
			return decisionFromRule(r), true
		case hostPreflightNeedHostname:
			if r.Rule.Action != config.ActionDirect {
				return Decision{}, false
			}
		case hostPreflightNoMatch:
			continue
		}
	}
	return Decision{Action: config.ActionDirect}, true
}

func decisionFromRule(r CompiledRule) Decision {
	return Decision{
		Matched: true,
		RuleID:  r.Rule.ID,
		Rule:    r.Rule.Name,
		Action:  r.Rule.Action,
		ProxyID: r.Rule.ProxyID,
		ChainID: r.Rule.ChainID,
	}
}

func (r CompiledRule) matchApp(path string, pid uint32) bool {
	if r.appsAny {
		return true
	}
	path = normalizeWindowsPath(path)
	base := pathBaseAny(path)
	for _, p := range r.apps {
		if p.pidOnly {
			if pid != 0 && pid == p.pid {
				return true
			}
			continue
		}
		if p.fullPath {
			if wildcardMatch(p.raw, path) {
				return true
			}
		} else if wildcardMatch(p.raw, base) {
			return true
		}
	}
	return false
}

func (r CompiledRule) matchHost(hostname string, ip netip.Addr, computerName string) bool {
	if r.hostsAny {
		return true
	}
	h := strings.ToLower(strings.TrimSpace(hostname))
	ipStr := ""
	for _, p := range r.hosts {
		switch p.kind {
		case hostAny:
			return true
		case hostComputerName:
			if h != "" && h == computerName {
				return true
			}
		case hostExactName:
			if h != "" && h == p.raw {
				return true
			}
		case hostGlobName:
			if h != "" && wildcardMatch(p.raw, h) {
				return true
			}
		case hostExactIP:
			if ip.IsValid() && ip == p.ip {
				return true
			}
		case hostCIDR:
			if ip.IsValid() && p.pref.Contains(ip) {
				return true
			}
		case hostIPRange:
			if ip.IsValid() && ipCompare(ip, p.ip) >= 0 && ipCompare(ip, p.end) <= 0 {
				return true
			}
		case hostGlobIP:
			if ipStr == "" && ip.IsValid() {
				ipStr = strings.ToLower(ip.String())
			}
			if ip.IsValid() && wildcardMatch(p.raw, ipStr) {
				return true
			}
		}
	}
	return false
}

type hostPreflightState int

const (
	hostPreflightNoMatch hostPreflightState = iota
	hostPreflightMatch
	hostPreflightNeedHostname
)

func (r CompiledRule) preflightHost(hostname string, ip netip.Addr, computerName string) hostPreflightState {
	if r.hostsAny {
		return hostPreflightMatch
	}
	if strings.TrimSpace(hostname) != "" {
		if r.matchHost(hostname, ip, computerName) {
			return hostPreflightMatch
		}
		return hostPreflightNoMatch
	}
	if r.matchHost("", ip, computerName) {
		return hostPreflightMatch
	}
	if r.hostnameDependent {
		return hostPreflightNeedHostname
	}
	return hostPreflightNoMatch
}

func (r CompiledRule) matchPort(port uint16) bool {
	if r.portsAny {
		return true
	}
	for _, pr := range r.ports {
		if port >= pr.from && port <= pr.to {
			return true
		}
	}
	return false
}

func normalizeWindowsPath(path string) string {
	path = strings.TrimSpace(strings.ReplaceAll(path, "/", `\`))
	return strings.ToLower(path)
}

func pathBaseAny(path string) string {
	path = normalizeWindowsPath(path)
	path = strings.TrimRight(path, `\`)
	if idx := strings.LastIndex(path, `\`); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func wildcardMatch(pattern, value string) bool {
	pattern = strings.ToLower(pattern)
	value = strings.ToLower(value)
	pi, vi := 0, 0
	star := -1
	match := 0
	for vi < len(value) {
		if pi < len(pattern) && (pattern[pi] == value[vi] || pattern[pi] == '?') {
			pi++
			vi++
			continue
		}
		if pi < len(pattern) && pattern[pi] == '*' {
			star = pi
			match = vi
			pi++
			continue
		}
		if star != -1 {
			pi = star + 1
			match++
			vi = match
			continue
		}
		return false
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func ipCompare(a, b netip.Addr) int {
	aa := a.As16()
	bb := b.As16()
	for i := 0; i < len(aa); i++ {
		if aa[i] < bb[i] {
			return -1
		}
		if aa[i] > bb[i] {
			return 1
		}
	}
	return 0
}
