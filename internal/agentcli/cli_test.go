package agentcli

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/control"
)

func runCLI(t *testing.T, args []string, input any) (int, []byte, []byte) {
	t.Helper()
	var stdin []byte
	if raw, ok := input.(string); ok {
		stdin = []byte(raw)
	} else if input != nil {
		var err error
		stdin, err = json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	code := Run(args, bytes.NewReader(stdin), &stdout, &stderr)
	if code == 0 && stderr.Len() != 0 {
		t.Fatalf("success stderr: %s", stderr.Bytes())
	}
	if code != 0 && stdout.Len() != 0 {
		t.Fatalf("failure stdout: %s", stdout.Bytes())
	}
	return code, stdout.Bytes(), stderr.Bytes()
}

func assertError(t *testing.T, code int, stderr []byte, wantExit int, wantCode string) {
	t.Helper()
	var response struct {
		Error cliError `json:"error"`
	}
	if err := json.Unmarshal(stderr, &response); err != nil {
		t.Fatalf("invalid error JSON %s: %v", stderr, err)
	}
	if code != wantExit || response.Error.Code != wantCode {
		t.Fatalf("exit=%d error=%s, want %d/%s", code, stderr, wantExit, wantCode)
	}
}

func TestLocalCommandsDoNotDiscoverOrCreateConfiguration(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent", "config.json")
	t.Setenv("PITCHPROX_CONFIG", missing)
	t.Setenv("PITCHPROX_CONTROL_URL", "https://not-loopback.invalid")
	for _, command := range []string{"schema", "--help"} {
		code, out, err := runCLI(t, []string{command}, nil)
		if code != 0 || len(out) == 0 {
			t.Fatalf("%s: code %d, %s", command, code, err)
		}
	}
	cfg := config.DefaultConfig()
	cfg.Rules[0].Name = "  Local  "
	code, out, err := runCLI(t, []string{"config", "validate", "--file", "-"}, cfg)
	if code != 0 {
		t.Fatalf("validate: %s", err)
	}
	var canonical config.Config
	if err := json.Unmarshal(out, &canonical); err != nil || canonical.Rules[0].Name != "Local" {
		t.Fatalf("canonical config: %s (%v)", out, err)
	}
	if _, err := os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
		t.Fatalf("local command created data directory: %v", err)
	}
}

func TestSchemaDescribesActualInputsAndMutationContract(t *testing.T) {
	code, out, stderr := runCLI(t, []string{"schema"}, nil)
	if code != 0 {
		t.Fatalf("schema: %s", stderr)
	}
	var guide struct {
		ProtocolVersion int   `json:"protocol_version"`
		Commands        []any `json:"commands"`
		ConfigSchema    struct {
			Properties map[string]any `json:"properties"`
		} `json:"config_schema"`
		RuleSchema struct {
			Properties map[string]any `json:"properties"`
		} `json:"rule_schema"`
		Semantics map[string]string `json:"mutation_semantics"`
	}
	if err := json.Unmarshal(out, &guide); err != nil {
		t.Fatal(err)
	}
	if guide.ProtocolVersion != 1 || len(guide.Commands) != 10 || len(guide.ConfigSchema.Properties) != reflect.TypeOf(config.Config{}).NumField() || len(guide.RuleSchema.Properties) != reflect.TypeOf(config.Rule{}).NumField() {
		t.Fatalf("incomplete schema: %+v", guide)
	}
	for _, key := range []string{"revision", "upsert", "new_rule_position", "disruption", "ambiguous_write", "result"} {
		if guide.Semantics[key] == "" {
			t.Errorf("missing mutation contract %s", key)
		}
	}
}

func TestStrictInputAndUsageErrorsAreLocal(t *testing.T) {
	t.Setenv("PITCHPROX_CONTROL_URL", "https://must-not-discover.invalid")
	for _, args := range [][]string{
		{}, {"config", "apply"}, {"rules", "delete", "--id", "x"},
		{"rules", "move", "--id", "x", "--if-revision", "2026-01-01T00:00:00Z"},
		{"status", "--file", "x"}, {"config", "get", "--url", "x", "--url", "y"},
		{"rules", "upsert", "--file", "-", "--if-revision", "bad"},
	} {
		code, _, stderr := runCLI(t, args, `{}`)
		assertError(t, code, stderr, 2, "usage_error")
	}
	for _, body := range []string{`null`, `{ "http":null }`, `{ "unknown":1 }`, `{ "rules":[], "rules":[] }`, `{} {}`} {
		code, _, stderr := runCLI(t, []string{"config", "validate", "--file", "-"}, body)
		assertError(t, code, stderr, 2, "invalid_json")
	}
	cfg := config.DefaultConfig()
	cfg.Rules[0].TargetPorts = "not-a-port"
	code, _, stderr := runCLI(t, []string{"config", "validate", "--file", "-"}, cfg)
	assertError(t, code, stderr, 2, "validation_error")
	cfg = config.DefaultConfig()
	cfg.UpdatedAt = time.Time{}
	code, _, stderr = runCLI(t, []string{"config", "apply", "--file", "-"}, cfg)
	assertError(t, code, stderr, 2, "revision_required")
}

func TestNormalizeURLRejectsNonLoopbackAndAmbiguousOrigins(t *testing.T) {
	for _, raw := range []string{
		"http://example.test:80", "http://192.168.0.1", "https://127.0.0.1", "http://127.0.0.1/path",
		"http://user:password@127.0.0.1", "http://127.0.0.1?x=1", "http://127.0.0.1#fragment",
		"http://127.0.0.1:0", "http://127.0.0.1:65536", "http://[::1%25lo]:80", "http://127.0.0.1:bad",
	} {
		if _, err := normalizeURL(raw); err == nil {
			t.Errorf("accepted unsafe URL %s", raw)
		}
	}
	for raw, want := range map[string]string{
		"http://localhost:18080/": "http://localhost:18080", "http://[::1]:18080": "http://[::1]:18080", "http://127.9.8.7": "http://127.9.8.7:80",
	} {
		got, err := normalizeURL(raw)
		if err != nil || got != want {
			t.Errorf("normalize %s = %s, %v; want %s", raw, got, err, want)
		}
	}
}

func TestDiscoveryPriorityDoesNotModifyConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{"http":{"listen":"127.0.0.1:19001"}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PITCHPROX_CONFIG", path)
	t.Setenv("PITCHPROX_CONTROL_URL", "")
	if got, err := discoverURL(""); err != nil || got != "http://127.0.0.1:19001" {
		t.Fatalf("config discovery = %s, %v", got, err)
	}
	t.Setenv("PITCHPROX_CONTROL_URL", "http://127.0.0.1:19002")
	if got, err := discoverURL(""); err != nil || got != "http://127.0.0.1:19002" {
		t.Fatalf("env discovery = %s, %v", got, err)
	}
	if got, err := discoverURL("http://127.0.0.1:19003"); err != nil || got != "http://127.0.0.1:19003" {
		t.Fatalf("explicit discovery = %s, %v", got, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, after) {
		t.Fatalf("discovery changed config: %s, %v", after, err)
	}
}

type testControl struct {
	t        *testing.T
	mu       sync.Mutex
	cfg      config.Config
	requests []control.ConfigRequest
	methods  []string
	server   *httptest.Server
}

func newTestControl(t *testing.T) *testControl {
	t.Helper()
	cfg, err := control.ValidateConfig(config.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	s := &testControl{t: t, cfg: cfg}
	s.server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.server.Close)
	return s
}

func (s *testControl) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("X-PitchProx-Agent") != "1" {
		s.t.Error("missing agent header")
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		if r.URL.Path == statusEndpoint {
			_ = json.NewEncoder(w).Encode(control.Status{ProtocolVersion: 1, Version: "test", UpdatedAt: s.cfg.UpdatedAt})
		} else if r.URL.Path == configEndpoint {
			_ = json.NewEncoder(w).Encode(s.cfg)
		} else {
			s.t.Errorf("unexpected GET %s", r.URL.Path)
			w.WriteHeader(404)
		}
		return
	}
	var request control.ConfigRequest
	data, err := io.ReadAll(r.Body)
	if err != nil {
		s.t.Error(err)
		w.WriteHeader(400)
		return
	}
	if err := control.DecodeJSON(data, &request); err != nil {
		s.t.Error(err)
		w.WriteHeader(400)
		return
	}
	s.requests = append(s.requests, request)
	s.methods = append(s.methods, r.Method+" "+r.URL.Path)
	previous := s.cfg.UpdatedAt
	if !request.ExpectedUpdatedAt.IsZero() && !request.ExpectedUpdatedAt.Equal(previous) {
		w.WriteHeader(409)
		_ = json.NewEncoder(w).Encode(control.ErrorResponse{Error: control.APIError{Code: "revision_conflict", Message: "changed", CurrentUpdatedAt: previous}})
		return
	}
	result := control.ConfigResult{Config: request.Config, PreviousUpdatedAt: previous, Plan: control.ApplyPlan{Mode: "hot_reload", ConnectionsPreserved: true, ListeningAddress: request.Config.HTTP.Listen}}
	if r.Method == http.MethodPut && !request.DryRun {
		result.Applied = true
		result.Config.UpdatedAt = previous.Add(time.Nanosecond)
		s.cfg = result.Config
	}
	_ = json.NewEncoder(w).Encode(result)
}

func TestReadCommandsUseAgentControlWithoutWebUI(t *testing.T) {
	server := newTestControl(t)
	for _, args := range [][]string{{"status"}, {"config", "get"}, {"rules", "list"}} {
		code, out, stderr := runCLI(t, append(args, "--url", server.server.URL), nil)
		if code != 0 || !json.Valid(out) {
			t.Fatalf("%v: exit %d out %s err %s", args, code, out, stderr)
		}
		if args[0] == "config" {
			var cfg config.Config
			server.mu.Lock()
			matches := json.Unmarshal(out, &cfg) == nil && reflect.DeepEqual(cfg, server.cfg)
			server.mu.Unlock()
			if !matches {
				t.Fatalf("configuration export changed: %s", out)
			}
		}
	}
}

func TestConfigPlanWithoutRevisionIsNonMutating(t *testing.T) {
	server := newTestControl(t)
	before := config.Clone(server.cfg)
	candidate := config.Clone(before)
	candidate.UpdatedAt = time.Time{}
	candidate.Rules[0].Name = "proposed"
	code, _, stderr := runCLI(t, []string{"config", "plan", "--file", "-", "--url", server.server.URL}, candidate)
	if code != 0 {
		t.Fatalf("plan: %s", stderr)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if !reflect.DeepEqual(server.cfg, before) || len(server.requests) != 1 || !server.requests[0].DryRun || server.methods[0] != "POST "+configEndpoint+"/validate" {
		t.Fatalf("plan changed state: %+v %+v", server.requests, server.methods)
	}
}

func TestConfigApplyCarriesExactRevisionAndOptIn(t *testing.T) {
	server := newTestControl(t)
	candidate := config.Clone(server.cfg)
	candidate.RetentionMinutes = 20
	code, out, stderr := runCLI(t, []string{"--url", server.server.URL, "config", "apply", "--file", "-", "--allow-disruptive"}, candidate)
	if code != 0 {
		t.Fatalf("apply: %s", stderr)
	}
	var result control.ConfigResult
	if err := json.Unmarshal(out, &result); err != nil || !result.Applied || !result.PreviousUpdatedAt.Equal(candidate.UpdatedAt) || !result.Config.UpdatedAt.After(candidate.UpdatedAt) {
		t.Fatalf("apply result: %s %v", out, err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	request := server.requests[0]
	if request.DryRun || !request.AllowDisruptive || !request.ExpectedUpdatedAt.Equal(candidate.UpdatedAt) || server.methods[0] != "PUT "+configEndpoint {
		t.Fatalf("request %+v", request)
	}
}

func TestRuleMutationsPreserveUnrelatedConfiguration(t *testing.T) {
	for _, mode := range []string{"upsert_existing", "insert_default", "insert_after", "delete", "move"} {
		t.Run(mode, func(t *testing.T) {
			server := newTestControl(t)
			server.cfg.Proxies = []config.ProxyProfile{{ID: "unused", Name: "Keep", Type: "socks5", Address: "127.0.0.1:1080", Username: "user", Password: "secret"}}
			server.cfg.Rules[0].Notes = "keep notes"
			before := config.Clone(server.cfg)
			revision := before.UpdatedAt.Format(time.RFC3339Nano)
			base := []string{"--url", server.server.URL, "rules"}
			var args []string
			var input any
			var wantIDs []string
			switch mode {
			case "upsert_existing":
				args = []string{"upsert", "--file", "-"}
				changed := before.Rules[0]
				changed.Name = "Renamed"
				input = changed
				wantIDs = []string{"localhost", "default"}
			case "insert_default":
				args = []string{"upsert", "--file", "-"}
				input = config.Rule{ID: "new", Action: config.ActionDirect}
				wantIDs = []string{"localhost", "new", "default"}
			case "insert_after":
				args = []string{"upsert", "--file", "-", "--after", "default"}
				input = config.Rule{ID: "new", Action: config.ActionDirect}
				wantIDs = []string{"localhost", "default", "new"}
			case "delete":
				args = []string{"delete", "--id", "localhost"}
				wantIDs = []string{"default"}
			case "move":
				args = []string{"move", "--id", "default", "--before", "localhost"}
				wantIDs = []string{"default", "localhost"}
			}
			args = append(append(base, args...), "--if-revision", revision)
			code, _, stderr := runCLI(t, args, input)
			if code != 0 {
				t.Fatalf("mutation: %s", stderr)
			}
			server.mu.Lock()
			defer server.mu.Unlock()
			var gotIDs []string
			for _, rule := range server.cfg.Rules {
				gotIDs = append(gotIDs, rule.ID)
			}
			if !reflect.DeepEqual(gotIDs, wantIDs) {
				t.Fatalf("rule order=%v want %v", gotIDs, wantIDs)
			}
			if !reflect.DeepEqual(server.cfg.Proxies, before.Proxies) || server.cfg.HTTP != before.HTTP || server.cfg.Transparent != before.Transparent {
				t.Fatalf("unrelated config changed: %+v", server.cfg)
			}
			for _, rule := range server.cfg.Rules {
				if rule.ID == "localhost" && rule.Notes != "keep notes" {
					t.Fatal("notes lost")
				}
			}
			if len(server.requests) != 1 || !server.requests[0].ExpectedUpdatedAt.Equal(before.UpdatedAt) {
				t.Fatalf("mutation lost CAS: %+v", server.requests)
			}
		})
	}
}

func TestRuleMutationRejectsStaleRevisionWithoutWriting(t *testing.T) {
	server := newTestControl(t)
	code, _, stderr := runCLI(t, []string{"rules", "delete", "--id", "localhost", "--if-revision", server.cfg.UpdatedAt.Add(-time.Second).Format(time.RFC3339Nano), "--url", server.server.URL}, nil)
	assertError(t, code, stderr, 3, "revision_conflict")
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.requests) != 0 {
		t.Fatal("wrote stale configuration")
	}
}

func TestRulePositionAndTargetErrorsDoNotWrite(t *testing.T) {
	for _, mode := range []string{"missing_target", "missing_anchor", "self_anchor", "no_default"} {
		t.Run(mode, func(t *testing.T) {
			server := newTestControl(t)
			args := []string{"rules", "move", "--id", "localhost", "--after", "missing"}
			var input any
			wantCode := "rule_not_found"
			switch mode {
			case "missing_target":
				args = []string{"rules", "delete", "--id", "missing"}
			case "self_anchor":
				args = []string{"rules", "move", "--id", "localhost", "--after", "localhost"}
				wantCode = "validation_error"
			case "no_default":
				server.cfg.Rules = server.cfg.Rules[:1]
				args = []string{"rules", "upsert", "--file", "-"}
				input = config.Rule{ID: "new"}
				wantCode = "position_required"
			}
			args = append(args, "--if-revision", server.cfg.UpdatedAt.Format(time.RFC3339Nano), "--url", server.server.URL)
			code, _, stderr := runCLI(t, args, input)
			assertError(t, code, stderr, 2, wantCode)
			server.mu.Lock()
			defer server.mu.Unlock()
			if len(server.requests) != 0 {
				t.Fatal("wrote invalid rule operation")
			}
		})
	}
}

func TestAPIErrorExitCodesAndOldServer(t *testing.T) {
	for _, test := range []struct {
		status   int
		code     string
		exit     int
		wantCode string
	}{
		{409, "revision_conflict", 3, "revision_conflict"}, {400, "disruptive_change", 4, "disruptive_change"},
		{400, "invalid_config", 2, "invalid_config"}, {503, "unavailable", 5, "unavailable"},
		{409, "update_busy", 5, "update_busy"}, {500, "activation_failed", 5, "activation_failed"}, {403, "forbidden", 5, "forbidden"},
		{404, "", 6, "upgrade_required"},
	} {
		t.Run(test.wantCode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				_ = json.NewEncoder(w).Encode(control.ErrorResponse{Error: control.APIError{Code: test.code, Message: "reason"}})
			}))
			defer server.Close()
			code, _, stderr := runCLI(t, []string{"config", "apply", "--file", "-", "--url", server.URL}, config.DefaultConfig())
			assertError(t, code, stderr, test.exit, test.wantCode)
		})
	}
}

func TestTransportRefusesRedirectsAndIgnoresProxyEnvironment(t *testing.T) {
	var redirected atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); w.WriteHeader(500) }))
	defer other.Close()
	t.Setenv("HTTP_PROXY", other.URL)
	t.Setenv("http_proxy", other.URL)
	t.Setenv("ALL_PROXY", other.URL)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 302) }))
	defer server.Close()
	code, _, stderr := runCLI(t, []string{"status", "--url", server.URL}, nil)
	assertError(t, code, stderr, 7, "protocol_error")
	if redirected.Load() != 0 {
		t.Fatalf("contacted redirect/proxy %d times", redirected.Load())
	}
}

func TestAmbiguousMutationNeverRetries(t *testing.T) {
	for _, broken := range []string{"disconnect", "bad_json", "missing_result"} {
		t.Run(broken, func(t *testing.T) {
			var puts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				puts.Add(1)
				if broken == "disconnect" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						_ = conn.Close()
					}
					return
				}
				if broken == "bad_json" {
					_, _ = io.WriteString(w, "{broken")
				} else {
					_, _ = io.WriteString(w, "{}")
				}
			}))
			defer server.Close()
			code, _, stderr := runCLI(t, []string{"config", "apply", "--file", "-", "--url", server.URL}, config.DefaultConfig())
			assertError(t, code, stderr, 8, "outcome_unknown")
			if puts.Load() != 1 {
				t.Fatalf("mutation attempts=%d", puts.Load())
			}
		})
	}
}

func TestInputSizeIsBounded(t *testing.T) {
	code, _, stderr := runCLI(t, []string{"config", "validate", "--file", "-"}, strings.Repeat(" ", maxJSONBytes+1))
	assertError(t, code, stderr, 2, "input_error")
}

func TestRuleWriteConflictAfterReadIsNotRetried(t *testing.T) {
	cfg := config.DefaultConfig()
	var reads, writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			reads.Add(1)
			_ = json.NewEncoder(w).Encode(cfg)
			return
		}
		writes.Add(1)
		var request control.ConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || !request.ExpectedUpdatedAt.Equal(cfg.UpdatedAt) {
			t.Errorf("lost read revision: %+v, %v", request, err)
		}
		w.WriteHeader(409)
		_ = json.NewEncoder(w).Encode(control.ErrorResponse{Error: control.APIError{Code: "revision_conflict", Message: "another writer won", CurrentUpdatedAt: cfg.UpdatedAt.Add(time.Nanosecond)}})
	}))
	defer server.Close()
	code, _, stderr := runCLI(t, []string{"rules", "delete", "--id", "localhost", "--if-revision", cfg.UpdatedAt.Format(time.RFC3339Nano), "--url", server.URL}, nil)
	assertError(t, code, stderr, 3, "revision_conflict")
	if reads.Load() != 1 || writes.Load() != 1 {
		t.Fatalf("attempts reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestNoOpApplyDoesNotRequireAdvancingRevision(t *testing.T) {
	cfg := config.DefaultConfig()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(control.ConfigResult{Config: cfg, PreviousUpdatedAt: cfg.UpdatedAt, Plan: control.ApplyPlan{Mode: "no_change", ConnectionsPreserved: true, ListeningAddress: cfg.HTTP.Listen}})
	}))
	defer server.Close()
	code, out, stderr := runCLI(t, []string{"config", "apply", "--file", "-", "--url", server.URL}, cfg)
	if code != 0 {
		t.Fatalf("no-op failed: %s", stderr)
	}
	var result control.ConfigResult
	if err := json.Unmarshal(out, &result); err != nil || result.Applied || !result.Config.UpdatedAt.Equal(cfg.UpdatedAt) {
		t.Fatalf("no-op result: %s, %v", out, err)
	}
}

func TestUpsertFirstRuleAfterDeletingAllRules(t *testing.T) {
	server := newTestControl(t)
	server.cfg.Rules = nil
	revision := server.cfg.UpdatedAt
	rule := config.Rule{ID: "first", Name: "First", Enabled: true, Action: config.ActionDirect}
	code, _, stderr := runCLI(t, []string{"rules", "upsert", "--file", "-", "--if-revision", revision.Format(time.RFC3339Nano), "--url", server.server.URL}, rule)
	if code != 0 {
		t.Fatalf("first insertion: %s", stderr)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.cfg.Rules) != 1 || server.cfg.Rules[0].ID != "first" || len(server.requests) != 1 || !server.requests[0].ExpectedUpdatedAt.Equal(revision) {
		t.Fatalf("first insertion lost rule or CAS: %+v", server.cfg)
	}
}

func TestEmptyRulesStillRejectExplicitMissingAnchor(t *testing.T) {
	server := newTestControl(t)
	server.cfg.Rules = nil
	code, _, stderr := runCLI(t, []string{"rules", "upsert", "--file", "-", "--before", "missing", "--if-revision", server.cfg.UpdatedAt.Format(time.RFC3339Nano), "--url", server.server.URL}, config.Rule{ID: "first"})
	assertError(t, code, stderr, 2, "rule_not_found")
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.requests) != 0 {
		t.Fatal("explicit missing anchor still wrote a rule")
	}
}

func TestLocalhostDiscoveryReachesEitherLoopbackFamily(t *testing.T) {
	for _, address := range []string{"localhost:0", "127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			listener, err := net.Listen("tcp", address)
			if err != nil {
				t.Skipf("loopback family unavailable: %v", err)
			}
			t.Logf("net.Listen(%q) selected %s", address, listener.Addr())
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(control.Status{ProtocolVersion: 1})
			}))
			_ = server.Listener.Close()
			server.Listener = listener
			server.Start()
			defer server.Close()
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(`{"http":{"listen":"localhost:`+port+`"}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PITCHPROX_CONFIG", path)
			t.Setenv("PITCHPROX_CONTROL_URL", "")
			code, _, stderr := runCLI(t, []string{"status"}, nil)
			if code != 0 {
				t.Fatalf("localhost discovery failed for listener %s: %s", listener.Addr(), stderr)
			}
		})
	}
}
