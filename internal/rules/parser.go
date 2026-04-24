package rules

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

func splitField(input string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQuotes := false
	flush := func() {
		token := normalizeFieldToken(cur.String())
		if token != "" {
			out = append(out, token)
		}
		cur.Reset()
	}
	for _, r := range input {
		switch r {
		case '"':
			inQuotes = !inQuotes
			cur.WriteRune(r)
		case ';', ',', '\n', '\r':
			if inQuotes {
				cur.WriteRune(r)
			} else {
				flush()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if inQuotes {
		return nil, fmt.Errorf("unclosed quote")
	}
	flush()
	return out, nil
}

func normalizeFieldToken(raw string) string {
	token := strings.TrimSpace(raw)
	if len(token) >= 2 && token[0] == '"' && token[len(token)-1] == '"' {
		token = strings.TrimSpace(token[1 : len(token)-1])
	}
	return token
}

type appPattern struct {
	raw      string
	fullPath bool
	pid      uint32
	pidOnly  bool
}

type hostKind int

const (
	hostAny hostKind = iota
	hostExactName
	hostGlobName
	hostComputerName
	hostExactIP
	hostCIDR
	hostIPRange
	hostGlobIP
)

type hostPattern struct {
	kind hostKind
	raw  string
	ip   netip.Addr
	end  netip.Addr
	pref netip.Prefix
}

type portRange struct {
	from uint16
	to   uint16
}

func parseApplications(input string) ([]appPattern, bool, error) {
	tokens, err := splitField(input)
	if err != nil {
		return nil, false, err
	}
	if len(tokens) == 0 {
		return nil, true, nil
	}
	if len(tokens) == 1 && (strings.EqualFold(tokens[0], "Any") || tokens[0] == "*") {
		return nil, true, nil
	}
	out := make([]appPattern, 0, len(tokens))
	for _, token := range tokens {
		if strings.EqualFold(token, "Any") || token == "*" {
			return nil, true, nil
		}
		if pid, ok := parsePIDToken(token); ok {
			out = append(out, appPattern{pid: pid, pidOnly: true})
			continue
		}
		token = strings.ReplaceAll(token, "/", `\`)
		out = append(out, appPattern{
			raw:      strings.ToLower(token),
			fullPath: strings.Contains(token, `\`) || strings.Contains(token, `:`),
		})
	}
	return out, false, nil
}

func parsePIDToken(token string) (uint32, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return 0, false
	}
	for _, r := range token {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(token, 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}

func parseHosts(input string) ([]hostPattern, bool, error) {
	tokens, err := splitField(input)
	if err != nil {
		return nil, false, err
	}
	if len(tokens) == 0 {
		return nil, true, nil
	}
	if len(tokens) == 1 && strings.EqualFold(tokens[0], "Any") {
		return nil, true, nil
	}
	out := make([]hostPattern, 0, len(tokens))
	for _, token := range tokens {
		if strings.EqualFold(token, "Any") {
			return nil, true, nil
		}
		if strings.EqualFold(token, "%ComputerName%") {
			out = append(out, hostPattern{kind: hostComputerName, raw: token})
			continue
		}
		if pref, err := netip.ParsePrefix(token); err == nil {
			out = append(out, hostPattern{kind: hostCIDR, raw: token, pref: pref})
			continue
		}
		if parts := strings.SplitN(token, "-", 2); len(parts) == 2 {
			if a, errA := netip.ParseAddr(strings.TrimSpace(parts[0])); errA == nil {
				if b, errB := netip.ParseAddr(strings.TrimSpace(parts[1])); errB == nil {
					out = append(out, hostPattern{kind: hostIPRange, raw: token, ip: a, end: b})
					continue
				}
			}
		}
		if ip, err := netip.ParseAddr(token); err == nil {
			out = append(out, hostPattern{kind: hostExactIP, raw: token, ip: ip})
			continue
		}
		if start, end, ok := parseIPv4StarGlobRange(token); ok {
			out = append(out, hostPattern{kind: hostIPRange, raw: token, ip: start, end: end})
			continue
		}
		if looksLikeIPGlob(token) {
			out = append(out, hostPattern{kind: hostGlobIP, raw: strings.ToLower(token)})
			continue
		}
		if strings.ContainsAny(token, "*?") {
			out = append(out, hostPattern{kind: hostGlobName, raw: strings.ToLower(token)})
			continue
		}
		out = append(out, hostPattern{kind: hostExactName, raw: strings.ToLower(token)})
	}
	return out, false, nil
}

func parsePorts(input string) ([]portRange, bool, error) {
	tokens, err := splitField(input)
	if err != nil {
		return nil, false, err
	}
	if len(tokens) == 0 {
		return nil, true, nil
	}
	if len(tokens) == 1 && strings.EqualFold(tokens[0], "Any") {
		return nil, true, nil
	}
	out := make([]portRange, 0, len(tokens))
	for _, token := range tokens {
		if strings.EqualFold(token, "Any") {
			return nil, true, nil
		}
		if parts := strings.SplitN(token, "-", 2); len(parts) == 2 {
			a, err := parsePort(parts[0])
			if err != nil {
				return nil, false, err
			}
			b, err := parsePort(parts[1])
			if err != nil {
				return nil, false, err
			}
			if a > b {
				a, b = b, a
			}
			out = append(out, portRange{from: a, to: b})
			continue
		}
		p, err := parsePort(token)
		if err != nil {
			return nil, false, err
		}
		out = append(out, portRange{from: p, to: p})
	}
	return out, false, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(n), nil
}

func looksLikeIPGlob(s string) bool {
	if strings.Contains(s, ":") {
		return strings.ContainsAny(s, "*?")
	}
	if !strings.ContainsAny(s, "*?") {
		return false
	}
	for _, r := range s {
		if (r >= '0' && r <= '9') || r == '.' || r == '*' || r == '?' {
			continue
		}
		return false
	}
	return true
}

func parseIPv4StarGlobRange(s string) (netip.Addr, netip.Addr, bool) {
	if strings.ContainsAny(s, ":?") || !strings.Contains(s, "*") {
		return netip.Addr{}, netip.Addr{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return netip.Addr{}, netip.Addr{}, false
	}
	var lo, hi [4]byte
	for i, part := range parts {
		part = strings.TrimSpace(part)
		switch part {
		case "*":
			lo[i], hi[i] = 0, 255
		default:
			if strings.Contains(part, "*") {
				return netip.Addr{}, netip.Addr{}, false
			}
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 || n > 255 {
				return netip.Addr{}, netip.Addr{}, false
			}
			lo[i], hi[i] = byte(n), byte(n)
		}
	}
	return netip.AddrFrom4(lo), netip.AddrFrom4(hi), true
}
