package rules

import (
	"net/netip"
	"testing"

	"github.com/openai/pitchprox/internal/config"
)

func TestEngineMatch(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{
		{ID: "r1", Name: "Localhost", Enabled: true, Applications: `"C:\Program Files\JetBrains\*"; firefox.exe`, TargetHosts: "127.0.0.1; ::1", TargetPorts: "Any", Action: config.ActionDirect},
		{ID: "r2", Name: "Proxy all 443", Enabled: true, Applications: "*", TargetHosts: "Any", TargetPorts: "443", Action: config.ActionProxy, ProxyID: "p1"},
	}}
	eng, err := Compile(cfg, "WORKSTATION")
	if err != nil {
		t.Fatal(err)
	}
	d := eng.Match(Request{AppPath: `C:\Program Files\JetBrains\IDE\bin\idea64.exe`, TargetIP: netip.MustParseAddr("127.0.0.1"), TargetPort: 8080})
	if !d.Matched || d.RuleID != "r1" {
		t.Fatalf("expected r1, got %+v", d)
	}
	d = eng.Match(Request{AppPath: `C:\Tools\firefox.exe`, TargetIP: netip.MustParseAddr("8.8.8.8"), TargetPort: 443})
	if !d.Matched || d.RuleID != "r2" || d.Action != config.ActionProxy {
		t.Fatalf("expected r2 proxy, got %+v", d)
	}
}

func TestSplitFieldSupportsSemicolonNewlineAndComma(t *testing.T) {
	tokens, err := splitField("github.com;\ndownload.jetbrains.com\r\nplugins.jetbrains.com, \"quoted,value\"")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"github.com", "download.jetbrains.com", "plugins.jetbrains.com", "quoted,value"}
	if len(tokens) != len(want) {
		t.Fatalf("unexpected token count: got %d want %d (%v)", len(tokens), len(want), tokens)
	}
	for i := range want {
		if tokens[i] != want[i] {
			t.Fatalf("token %d: got %q want %q", i, tokens[i], want[i])
		}
	}
}

func TestSplitFieldRejectsUnclosedQuote(t *testing.T) {
	if _, err := splitField(`"firefox.exe; chrome.exe`); err == nil {
		t.Fatal("expected unclosed quote error")
	}
}

func TestEngineMatchSupportsMultilineHosts(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{{
		ID:           "r1",
		Name:         "JetBrains",
		Enabled:      true,
		Applications: "*",
		TargetHosts:  "www.jetbrains.com; resources.jetbrains.com\ndownload.jetbrains.com\r\nplugins.jetbrains.com",
		TargetPorts:  "Any",
		Action:       config.ActionProxy,
		ProxyID:      "p1",
	}}}
	eng, err := Compile(cfg, "WORKSTATION")
	if err != nil {
		t.Fatal(err)
	}
	d := eng.Match(Request{AppPath: `C:\Tools\idea64.exe`, Hostname: "download.jetbrains.com", TargetPort: 443})
	if !d.Matched || d.RuleID != "r1" || d.Action != config.ActionProxy {
		t.Fatalf("expected multiline host match, got %+v", d)
	}
}

func TestEngineMatchSupportsMultilineApplications(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{{
		ID:           "r1",
		Name:         "Apps",
		Enabled:      true,
		Applications: "chrome.exe\nbrave.exe; firefox.exe",
		TargetHosts:  "Any",
		TargetPorts:  "Any",
		Action:       config.ActionProxy,
		ProxyID:      "p1",
	}}}
	eng, err := Compile(cfg, "WORKSTATION")
	if err != nil {
		t.Fatal(err)
	}
	d := eng.Match(Request{AppPath: `C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`, TargetPort: 443})
	if !d.Matched || d.RuleID != "r1" {
		t.Fatalf("expected multiline application match, got %+v", d)
	}
}

func TestEngineMatchSupportsPIDApplications(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{{
		ID: "r1", Name: "PID rule", Enabled: true, Applications: "12345", TargetHosts: "Any", TargetPorts: "Any", Action: config.ActionProxy, ProxyID: "p1",
	}}}
	eng, err := Compile(cfg, "WORKSTATION")
	if err != nil {
		t.Fatal(err)
	}
	d := eng.Match(Request{PID: 12345, AppPath: `C:\Tools\app.exe`, Hostname: "example.com", TargetPort: 443})
	if !d.Matched || d.RuleID != "r1" || d.Action != config.ActionProxy {
		t.Fatalf("expected PID rule match, got %+v", d)
	}
	d = eng.Match(Request{PID: 54321, AppPath: `C:\Tools\app.exe`, Hostname: "example.com", TargetPort: 443})
	if d.Matched {
		t.Fatalf("did not expect PID rule to match another process: %+v", d)
	}
}

func TestApplicationWildcardsAndQuotedPatterns(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{{
		ID:           "r1",
		Name:         "Apps",
		Enabled:      true,
		Applications: "fire*.exe\n\"*.bin\"\n\"C:\\Program Files\\JetBrains\\*\"",
		TargetHosts:  "Any",
		TargetPorts:  "Any",
		Action:       config.ActionProxy,
		ProxyID:      "p1",
	}}}
	eng, err := Compile(cfg, "WORKSTATION")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		path string
	}{
		{name: "wildcard exe", path: `C:\Apps\firefox.exe`},
		{name: "quoted basename glob", path: `C:\Tools\helper.bin`},
		{name: "quoted full path glob", path: `C:\Program Files\JetBrains\GoLand\bin\goland64.exe`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := eng.Match(Request{AppPath: tc.path, Hostname: "example.com", TargetPort: 443})
			if !d.Matched || d.RuleID != "r1" {
				t.Fatalf("expected application match for %s, got %+v", tc.path, d)
			}
		})
	}
}

func TestHostWildcardAndRangeMatching(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{{
		ID: "r1", Name: "LAN wildcard", Enabled: true, Applications: "*", TargetHosts: "192.168.1.*", TargetPorts: "Any", Action: config.ActionDirect,
	}, {
		ID: "r2", Name: "IP range", Enabled: true, Applications: "*", TargetHosts: "10.1.0.0-10.5.255.255", TargetPorts: "Any", Action: config.ActionProxy, ProxyID: "p1",
	}}}
	eng, err := Compile(cfg, "WORKSTATION")
	if err != nil {
		t.Fatal(err)
	}
	if d := eng.Match(Request{AppPath: `C:\Apps\app.exe`, TargetIP: netip.MustParseAddr("192.168.1.44"), TargetPort: 80}); !d.Matched || d.RuleID != "r1" {
		t.Fatalf("expected wildcard IP match, got %+v", d)
	}
	if d := eng.Match(Request{AppPath: `C:\Apps\app.exe`, TargetIP: netip.MustParseAddr("10.4.25.8"), TargetPort: 443}); !d.Matched || d.RuleID != "r2" {
		t.Fatalf("expected range match, got %+v", d)
	}
	if d := eng.Match(Request{AppPath: `C:\Apps\app.exe`, TargetIP: netip.MustParseAddr("10.6.0.1"), TargetPort: 443}); d.Matched && d.RuleID == "r2" {
		t.Fatalf("did not expect out-of-range IP to match r2: %+v", d)
	}
}

func TestIPv4StarGlobCompilesToRange(t *testing.T) {
	hosts, any, err := parseHosts("192.168.*.*")
	if err != nil {
		t.Fatalf("parseHosts: %v", err)
	}
	if any || len(hosts) != 1 {
		t.Fatalf("hosts = %+v any=%v, want one concrete range", hosts, any)
	}
	if hosts[0].kind != hostIPRange {
		t.Fatalf("host kind = %d, want hostIPRange", hosts[0].kind)
	}
	if !hosts[0].ip.IsValid() || !hosts[0].end.IsValid() {
		t.Fatalf("range bounds invalid: %+v", hosts[0])
	}
	if hosts[0].ip.String() != "192.168.0.0" || hosts[0].end.String() != "192.168.255.255" {
		t.Fatalf("range = %s-%s, want 192.168.0.0-192.168.255.255", hosts[0].ip, hosts[0].end)
	}
}

func TestExactUserSyntaxExamples(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{{
		ID:      "r1",
		Name:    "Examples",
		Enabled: true,
		Applications: `fire*.exe
"*.bin"
"C:\Program Files\JetBrains\*"`,
		TargetHosts: `192.168.1.*
10.1.0.0-10.5.255.255
www.jetbrains.com`,
		TargetPorts: "443; 8000-9000",
		Action:      config.ActionProxy,
		ProxyID:     "p1",
	}}}
	eng, err := Compile(cfg, "WORKSTATION")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		req  Request
	}{
		{name: "fire wildcard", req: Request{AppPath: `C:\Apps\firefox.exe`, TargetIP: netip.MustParseAddr("192.168.1.44"), TargetPort: 443}},
		{name: "quoted bin", req: Request{AppPath: `C:\Tools\helper.bin`, TargetIP: netip.MustParseAddr("10.2.3.4"), TargetPort: 443}},
		{name: "jetbrains path", req: Request{AppPath: `C:\Program Files\JetBrains\IDE\bin\idea64.exe`, Hostname: "www.jetbrains.com", TargetPort: 8001}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := eng.Match(tc.req)
			if !d.Matched || d.RuleID != "r1" {
				t.Fatalf("expected syntax example to match, got %+v", d)
			}
		})
	}
}

func TestPreflightDirectBypassForIPRule(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{
		{ID: "r1", Name: "LAN direct", Enabled: true, Applications: "*", TargetHosts: "192.168.1.*", TargetPorts: "443", Action: config.ActionDirect},
		{ID: "default", Name: "Default", Enabled: true, Applications: "*", TargetHosts: "Any", TargetPorts: "Any", Action: config.ActionProxy, ProxyID: "p1"},
	}}
	eng, err := Compile(cfg, "WORKSTATION")
	if err != nil {
		t.Fatal(err)
	}
	pre := eng.Preflight(Request{AppPath: `C:\Apps\firefox.exe`, TargetIP: netip.MustParseAddr("192.168.1.22"), TargetPort: 443})
	if !pre.Definitive || pre.Action != config.ActionDirect || pre.RuleID != "r1" {
		t.Fatalf("expected definitive direct preflight, got %+v", pre)
	}
}

func TestPreflightRequiresHostnameWhenEarlierHostRuleMayMatch(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{
		{ID: "r1", Name: "GitHub direct", Enabled: true, Applications: "*", TargetHosts: "github.com", TargetPorts: "443", Action: config.ActionDirect},
		{ID: "default", Name: "Default proxy", Enabled: true, Applications: "*", TargetHosts: "Any", TargetPorts: "Any", Action: config.ActionProxy, ProxyID: "p1"},
	}}
	eng, err := Compile(cfg, "WORKSTATION")
	if err != nil {
		t.Fatal(err)
	}
	pre := eng.Preflight(Request{AppPath: `C:\Apps\firefox.exe`, TargetIP: netip.MustParseAddr("140.82.121.4"), TargetPort: 443})
	if pre.Definitive || !pre.NeedsHostname || pre.RuleID != "r1" {
		t.Fatalf("expected hostname-dependent preflight, got %+v", pre)
	}
}

func TestPreflightSkipsHostnameOnlyDirectWhenLaterOutcomeIsDirect(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{
		{ID: "localhost", Name: "Localhost", Enabled: true, Applications: "*", TargetHosts: "localhost;127.0.0.1;::1;%ComputerName%", TargetPorts: "Any", Action: config.ActionDirect},
		{ID: "sentinel", Name: "Sentinel block", Enabled: true, Applications: "curl.exe", TargetHosts: "blocked.pitchprox.invalid", TargetPorts: "443", Action: config.ActionBlock},
		{ID: "default", Name: "Default direct", Enabled: true, Applications: "*", TargetHosts: "Any", TargetPorts: "Any", Action: config.ActionDirect},
	}}
	eng, err := Compile(cfg, "WORKSTATION")
	if err != nil {
		t.Fatal(err)
	}
	pre := eng.Preflight(Request{AppPath: `C:\Apps\codex.exe`, TargetIP: netip.MustParseAddr("104.18.32.47"), TargetPort: 443})
	if !pre.Definitive || pre.NeedsHostname || pre.Action != config.ActionDirect || pre.RuleID != "default" {
		t.Fatalf("expected definitive default direct without hostname sniff, got %+v", pre)
	}
}

func TestPreflightStillSniffsWhenLaterNonDirectMayMatch(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{
		{ID: "localhost", Name: "Localhost", Enabled: true, Applications: "*", TargetHosts: "localhost;127.0.0.1;::1;%ComputerName%", TargetPorts: "Any", Action: config.ActionDirect},
		{ID: "curl-direct", Name: "curl example direct", Enabled: true, Applications: "curl.exe", TargetHosts: "example.com", TargetPorts: "443", Action: config.ActionDirect},
		{ID: "curl-block", Name: "curl blocked host", Enabled: true, Applications: "curl.exe", TargetHosts: "blocked.pitchprox.invalid", TargetPorts: "443", Action: config.ActionBlock},
		{ID: "default", Name: "Default direct", Enabled: true, Applications: "*", TargetHosts: "Any", TargetPorts: "Any", Action: config.ActionDirect},
	}}
	eng, err := Compile(cfg, "WORKSTATION")
	if err != nil {
		t.Fatal(err)
	}
	pre := eng.Preflight(Request{AppPath: `C:\Windows\System32\curl.exe`, TargetIP: netip.MustParseAddr("104.20.23.154"), TargetPort: 443})
	if pre.Definitive || !pre.NeedsHostname || pre.Action != config.ActionDirect || pre.RuleID != "localhost" {
		t.Fatalf("expected hostname sniff to preserve later block possibility, got %+v", pre)
	}
}

func TestAllEnabledActionsDirect(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{{ID: "r1", Name: "A", Enabled: true, Applications: "*", TargetHosts: "Any", TargetPorts: "Any", Action: config.ActionDirect}}}
	eng, err := Compile(cfg, "WORKSTATION")
	if err != nil {
		t.Fatal(err)
	}
	if !eng.AllEnabledActionsDirect() {
		t.Fatal("expected all-enabled-direct optimization flag")
	}
}
