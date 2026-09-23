// Package agentcli implements the synchronous, headless control client.
package agentcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/control"
	"github.com/agentpitch/prox/internal/util"
)

const (
	maxJSONBytes   = control.MaxConfigBytes
	configEndpoint = "/api/control/agent/config"
	statusEndpoint = "/api/control/agent/status"
)

type cliError struct {
	Code             string     `json:"code"`
	Message          string     `json:"message"`
	CurrentUpdatedAt *time.Time `json:"current_updated_at,omitempty"`
	exit             int
}

func (e *cliError) Error() string { return e.Message }

func failure(code, message string, exit int) *cliError {
	return &cliError{Code: code, Message: message, exit: exit}
}

type invocation struct {
	command string
	flags   map[string]string
}

// Run executes arguments following "pitchProx ctl". It never starts the
// application, opens a browser, writes configuration files, or retries writes.
// Success is JSON on stdout; failures are JSON on stderr with a nonzero code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	result, err := execute(args, stdin)
	if err != nil {
		var reported *cliError
		if !errors.As(err, &reported) {
			reported = failure("internal_error", err.Error(), 7)
		}
		_ = json.NewEncoder(stderr).Encode(struct {
			Error *cliError `json:"error"`
		}{reported})
		return reported.exit
	}
	if help, ok := result.(helpText); ok {
		if _, err := io.WriteString(stdout, string(help)); err != nil {
			return 7
		}
		return 0
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_ = json.NewEncoder(stderr).Encode(struct {
			Error *cliError `json:"error"`
		}{failure("output_error", err.Error(), 7)})
		return 7
	}
	return 0
}

func execute(args []string, stdin io.Reader) (any, error) {
	inv, err := parseArgs(args)
	if err != nil {
		return nil, err
	}
	if inv.command == "help" {
		return helpText(usage), nil
	}
	if inv.command == "schema" {
		return machineGuide(), nil
	}
	var candidate config.Config
	if strings.HasPrefix(inv.command, "config ") && inv.command != "config get" {
		if err := readInput(inv.flags["file"], stdin, &candidate); err != nil {
			return nil, err
		}
		candidate, err = validateConfig(candidate)
		if err != nil {
			return nil, err
		}
		if inv.command == "config validate" {
			return candidate, nil
		}
		if inv.command == "config apply" && candidate.UpdatedAt.IsZero() {
			return nil, failure("revision_required", "config.updated_at is required; fetch config get before planning or applying changes", 2)
		}
	}
	var revision time.Time
	if value := inv.flags["if-revision"]; value != "" {
		revision, err = time.Parse(time.RFC3339Nano, value)
		if err != nil || revision.IsZero() {
			return nil, failure("usage_error", "--if-revision must be a nonzero RFC3339 timestamp", 2)
		}
	}
	var rule config.Rule
	if inv.command == "rules upsert" {
		if err := readInput(inv.flags["file"], stdin, &rule); err != nil {
			return nil, err
		}
		rule.ID = strings.TrimSpace(rule.ID)
		if rule.ID == "" {
			return nil, failure("validation_error", "rule.id is required", 2)
		}
	}
	baseURL, err := discoverURL(inv.flags["url"])
	if err != nil {
		return nil, err
	}
	client := newClient(baseURL)
	defer client.http.CloseIdleConnections()
	switch inv.command {
	case "status":
		data, err := client.request(http.MethodGet, statusEndpoint, nil, false)
		if err != nil {
			return nil, err
		}
		var status control.Status
		if err := json.Unmarshal(data, &status); err != nil || status.ProtocolVersion != control.ProtocolVersion {
			return nil, failure("protocol_error", "unsupported or missing agent protocol version", 7)
		}
		return status, nil
	case "config get":
		return client.getConfig()
	case "config plan", "config apply":
		return client.save(candidate, inv.command == "config plan", inv.flags["allow-disruptive"] == "true")
	case "rules list":
		current, err := client.getConfig()
		if err != nil {
			return nil, err
		}
		return map[string]any{"updated_at": current.UpdatedAt, "rules": current.Rules}, nil
	case "rules upsert", "rules delete", "rules move":
		current, err := client.getConfig()
		if err != nil {
			return nil, err
		}
		if !current.UpdatedAt.Equal(revision) {
			return nil, &cliError{Code: "revision_conflict", Message: "configuration changed; fetch config get and review changes before retrying", CurrentUpdatedAt: &current.UpdatedAt, exit: 3}
		}
		candidate, err = mutateRule(current, inv, rule)
		if err != nil {
			return nil, err
		}
		candidate, err = validateConfig(candidate)
		if err != nil {
			return nil, err
		}
		return client.save(candidate, false, inv.flags["allow-disruptive"] == "true")
	}
	return nil, failure("usage_error", "unknown command", 2)
}

func parseArgs(args []string) (invocation, error) {
	inv := invocation{flags: make(map[string]string)}
	var words []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			return invocation{command: "help"}, nil
		}
		if !strings.HasPrefix(arg, "-") {
			words = append(words, arg)
			continue
		}
		if !strings.HasPrefix(arg, "--") {
			return inv, failure("usage_error", "unknown option "+arg, 2)
		}
		key, value, hasValue := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		switch key {
		case "url", "file", "id", "if-revision", "before", "after":
			if !hasValue {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "--") {
					return inv, failure("usage_error", "--"+key+" requires a value", 2)
				}
				value = args[i]
			}
			if value == "" {
				return inv, failure("usage_error", "--"+key+" requires a nonempty value", 2)
			}
		case "allow-disruptive":
			if !hasValue {
				value = "true"
			}
			if value != "true" && value != "false" {
				return inv, failure("usage_error", "--allow-disruptive accepts true or false", 2)
			}
		default:
			return inv, failure("usage_error", "unknown option --"+key, 2)
		}
		if _, exists := inv.flags[key]; exists {
			return inv, failure("usage_error", "duplicate option --"+key, 2)
		}
		inv.flags[key] = value
	}
	inv.command = strings.Join(words, " ")
	allowed := "url"
	required := ""
	switch inv.command {
	case "help", "schema", "status", "config get", "rules list":
	case "config validate", "config plan":
		allowed += " file"
		required = "file"
	case "config apply":
		allowed += " file allow-disruptive"
		required = "file"
	case "rules upsert":
		allowed += " file if-revision before after allow-disruptive"
		required = "file if-revision"
	case "rules delete":
		allowed += " id if-revision allow-disruptive"
		required = "id if-revision"
	case "rules move":
		allowed += " id if-revision before after allow-disruptive"
		required = "id if-revision"
	default:
		return inv, failure("usage_error", "expected a control command; use pitchProx ctl --help", 2)
	}
	for key := range inv.flags {
		if !strings.Contains(" "+allowed+" ", " "+key+" ") {
			return inv, failure("usage_error", "--"+key+" is not valid for "+inv.command, 2)
		}
	}
	for _, key := range strings.Fields(required) {
		if inv.flags[key] == "" {
			return inv, failure("usage_error", "--"+key+" is required", 2)
		}
	}
	if inv.flags["before"] != "" && inv.flags["after"] != "" {
		return inv, failure("usage_error", "choose either --before or --after", 2)
	}
	if inv.command == "rules move" && inv.flags["before"] == "" && inv.flags["after"] == "" {
		return inv, failure("usage_error", "rules move requires --before or --after", 2)
	}
	return inv, nil
}

func readInput(path string, stdin io.Reader, out any) error {
	reader := stdin
	if path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return failure("input_error", "read input: "+err.Error(), 2)
		}
		defer file.Close()
		reader = file
	}
	if reader == nil {
		return failure("input_error", "stdin is unavailable", 2)
	}
	data, err := readBounded(reader)
	if err != nil {
		return failure("input_error", err.Error(), 2)
	}
	if err := control.DecodeJSON(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}), out); err != nil {
		return failure("invalid_json", "decode input: "+err.Error(), 2)
	}
	return nil
}

func readBounded(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxJSONBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxJSONBytes {
		return nil, fmt.Errorf("JSON exceeds %d bytes", maxJSONBytes)
	}
	return data, nil
}

func validateConfig(candidate config.Config) (config.Config, error) {
	candidate, err := control.ValidateConfig(candidate)
	if err != nil {
		return config.Config{}, failure("validation_error", err.Error(), 2)
	}
	return candidate, nil
}

func mutateRule(current config.Config, inv invocation, rule config.Rule) (config.Config, error) {
	out := config.Clone(current)
	id := inv.flags["id"]
	if inv.command == "rules upsert" {
		id = rule.ID
	}
	index := -1
	for i, existing := range out.Rules {
		if existing.ID == id {
			index = i
			break
		}
	}
	if index < 0 && inv.command != "rules upsert" {
		return out, failure("rule_not_found", "rule id not found: "+id, 2)
	}
	before, after := inv.flags["before"], inv.flags["after"]
	if before == id || after == id {
		return out, failure("validation_error", "a rule cannot be positioned relative to itself", 2)
	}
	if inv.command == "rules delete" {
		out.Rules = append(out.Rules[:index], out.Rules[index+1:]...)
		return out, nil
	}
	if inv.command == "rules move" {
		rule = out.Rules[index]
	}
	if index >= 0 && before == "" && after == "" {
		out.Rules[index] = rule
		return out, nil
	}
	if index >= 0 {
		out.Rules = append(out.Rules[:index], out.Rules[index+1:]...)
	}
	position := -1
	if before != "" || after != "" {
		for i, existing := range out.Rules {
			if existing.ID == before {
				position = i
				break
			}
			if existing.ID == after {
				position = i + 1
				break
			}
		}
		if position < 0 {
			return out, failure("rule_not_found", "position anchor rule not found", 2)
		}
	} else if len(out.Rules) == 0 {
		position = 0
	} else if defaultCatchAll(out.Rules[len(out.Rules)-1]) {
		position = len(out.Rules) - 1
	} else {
		return out, failure("position_required", "new rules require --before or --after when there is no final enabled default catch-all", 2)
	}
	out.Rules = append(out.Rules, config.Rule{})
	copy(out.Rules[position+1:], out.Rules[position:])
	out.Rules[position] = rule
	return out, nil
}

func defaultCatchAll(rule config.Rule) bool {
	any := func(value string) bool {
		return strings.TrimSpace(value) == "" || strings.EqualFold(strings.TrimSpace(value), "Any")
	}
	return rule.ID == "default" && rule.Enabled && (any(rule.Applications) || strings.TrimSpace(rule.Applications) == "*") && any(rule.TargetHosts) && any(rule.TargetPorts)
}

func discoverURL(explicit string) (string, error) {
	if explicit == "" {
		explicit = strings.TrimSpace(os.Getenv("PITCHPROX_CONTROL_URL"))
	}
	if explicit == "" {
		explicit = "http://127.0.0.1:18080"
		file, err := os.Open(util.ConfigPathReadOnly())
		if err == nil {
			defer file.Close()
			data, err := readBounded(file)
			if err != nil {
				return "", failure("discovery_error", "read existing config: "+err.Error(), 5)
			}
			var existing struct {
				HTTP config.HTTPConfig `json:"http"`
			}
			if err := json.Unmarshal(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}), &existing); err != nil {
				return "", failure("discovery_error", "parse existing config: "+err.Error(), 5)
			}
			if strings.TrimSpace(existing.HTTP.Listen) == "" {
				return "", failure("discovery_error", "existing config has no http.listen", 5)
			}
			explicit = "http://" + strings.TrimSpace(existing.HTTP.Listen)
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", failure("discovery_error", "read existing config: "+err.Error(), 5)
		}
	}
	return normalizeURL(explicit)
}

func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", failure("invalid_url", "--url must be an HTTP loopback origin without credentials, path, query, or fragment", 2)
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		host = "localhost"
	} else {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.IsLoopback() || ip.Zone() != "" {
			return "", failure("invalid_url", "control URL must use a literal loopback address or localhost", 2)
		}
		host = ip.String()
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", failure("invalid_url", "control URL port must be in 1..65535", 2)
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

type client struct {
	baseURL string
	http    *http.Client
}

func newClient(baseURL string) *client {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10,
		ResponseHeaderTimeout: 30 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if host == "localhost" {
				// A localhost listener may bind either family. Try literal
				// loopback addresses only; never resolve a hostname to a remote
				// peer. Fallback occurs before a connection/HTTP request exists,
				// so an unconfirmed mutation is still never sent a second time.
				conn, firstErr := dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
				if firstErr == nil || ctx.Err() != nil {
					return conn, firstErr
				}
				conn, secondErr := dialer.DialContext(ctx, network, net.JoinHostPort("::1", port))
				if secondErr != nil {
					return nil, errors.Join(firstErr, secondErr)
				}
				return conn, nil
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || !ip.IsLoopback() {
				return nil, errors.New("non-loopback control connection rejected")
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
	return &client{baseURL: baseURL, http: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *client) request(method, endpoint string, payload any, mutation bool) (json.RawMessage, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, failure("invalid_json", err.Error(), 2)
		}
		if len(data) > maxJSONBytes {
			return nil, failure("input_error", "request exceeds JSON size limit", 2)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.baseURL+endpoint, body)
	if err != nil {
		return nil, failure("invalid_url", err.Error(), 2)
	}
	req.Header.Set("X-PitchProx-Agent", "1")
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, transportFailure(err, mutation)
	}
	defer resp.Body.Close()
	data, err := readBounded(resp.Body)
	if err != nil {
		return nil, transportFailure(err, mutation)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, failure("upgrade_required", "server does not support agent control; upgrade the running pitchProx instance", 6)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, failure("protocol_error", "control server redirects are refused", 7)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var response struct {
			Error *cliError `json:"error"`
		}
		if err := json.Unmarshal(data, &response); err == nil && response.Error != nil && response.Error.Code != "" && response.Error.Message != "" {
			response.Error.exit = errorExit(response.Error.Code, resp.StatusCode)
			return nil, response.Error
		}
		return nil, failure("protocol_error", fmt.Sprintf("control server returned HTTP %d without a typed JSON error", resp.StatusCode), 7)
	}
	if !json.Valid(data) {
		if mutation {
			return nil, transportFailure(errors.New("control server returned invalid JSON"), true)
		}
		return nil, failure("protocol_error", "control server returned invalid JSON", 7)
	}
	return json.RawMessage(data), nil
}

func transportFailure(err error, mutation bool) *cliError {
	if mutation {
		return failure("outcome_unknown", "configuration write was not confirmed: "+err.Error()+"; do not retry automatically; run config get and compare the resulting configuration", 8)
	}
	return failure("unavailable", "control request failed: "+err.Error(), 5)
}

func errorExit(code string, status int) int {
	switch code {
	case "revision_conflict", "config_conflict":
		return 3
	case "disruptive_change", "disruptive_change_required", "disruptive_confirmation_required":
		return 4
	case "validation_error", "invalid_config", "invalid_request", "revision_required":
		return 2
	case "unavailable", "update_busy", "activation_failed", "forbidden":
		return 5
	}
	if status == http.StatusConflict || status == http.StatusPreconditionFailed {
		return 3
	}
	if status == http.StatusBadRequest || status == http.StatusUnprocessableEntity {
		return 2
	}
	return 7
}

func (c *client) getConfig() (config.Config, error) {
	data, err := c.request(http.MethodGet, configEndpoint, nil, false)
	if err != nil {
		return config.Config{}, err
	}
	var cfg config.Config
	if err := control.DecodeJSON(data, &cfg); err != nil || cfg.UpdatedAt.IsZero() {
		return config.Config{}, failure("protocol_error", "server configuration response is not a supported configuration with updated_at", 7)
	}
	return cfg, nil
}

func (c *client) save(candidate config.Config, dryRun, allowDisruptive bool) (json.RawMessage, error) {
	method, endpoint := http.MethodPut, configEndpoint
	if dryRun {
		method, endpoint = http.MethodPost, configEndpoint+"/validate"
	}
	data, err := c.request(method, endpoint, control.ConfigRequest{Config: candidate, ExpectedUpdatedAt: candidate.UpdatedAt, DryRun: dryRun, AllowDisruptive: allowDisruptive}, !dryRun)
	if err != nil {
		return nil, err
	}
	var response control.ConfigResult
	decodeErr := control.DecodeJSON(data, &response)
	if decodeErr == nil {
		decodeErr = validateSaveResult(response, candidate, dryRun)
	}
	if decodeErr != nil {
		if !dryRun {
			return nil, transportFailure(fmt.Errorf("invalid configuration result: %w", decodeErr), true)
		}
		return nil, failure("protocol_error", "invalid configuration preview: "+decodeErr.Error(), 7)
	}
	return data, nil
}

func validateSaveResult(result control.ConfigResult, candidate config.Config, dryRun bool) error {
	if result.PreviousUpdatedAt.IsZero() || (!candidate.UpdatedAt.IsZero() && !result.PreviousUpdatedAt.Equal(candidate.UpdatedAt)) {
		return errors.New("missing or mismatched previous_updated_at")
	}
	if _, err := control.ValidateConfig(result.Config); err != nil {
		return fmt.Errorf("invalid returned config: %w", err)
	}
	plan := result.Plan
	if plan.ListeningAddress != result.Config.HTTP.Listen || plan.ConnectionsPreserved == plan.RuntimeRestart {
		return errors.New("missing or inconsistent activation plan")
	}
	switch plan.Mode {
	case "no_change", "hot_reload":
		if plan.HTTPRebind || plan.RuntimeRestart {
			return errors.New("inconsistent activation mode")
		}
	case "listener_rebind":
		if !plan.HTTPRebind || plan.RuntimeRestart {
			return errors.New("inconsistent listener rebind plan")
		}
	case "runtime_restart":
		if !plan.RuntimeRestart {
			return errors.New("inconsistent runtime restart plan")
		}
	default:
		return errors.New("unsupported or missing activation mode")
	}
	if dryRun {
		if result.Applied {
			return errors.New("preview unexpectedly reports a write")
		}
		return nil
	}
	if result.Config.UpdatedAt.IsZero() {
		return errors.New("missing config.updated_at")
	}
	if result.Applied {
		if plan.Mode == "no_change" || !result.Config.UpdatedAt.After(result.PreviousUpdatedAt) {
			return errors.New("write did not advance the revision")
		}
	} else if plan.Mode != "no_change" || !result.Config.UpdatedAt.Equal(result.PreviousUpdatedAt) {
		return errors.New("unconfirmed write without a no-change plan")
	}
	return nil
}
