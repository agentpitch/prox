package agentcli

import (
	"time"

	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/control"
)

type helpText string

const usage = `pitchProx ctl [--url http://127.0.0.1:18080] COMMAND

  status                          Show running instance and protocol version
  schema                          Print the JSON command guide and input schemas
  config get                      Export the complete live configuration
  config validate --file PATH|-    Validate locally; print canonical configuration
  config plan --file PATH|-        Preview server activation without applying
  config apply --file PATH|- [--allow-disruptive]
  rules list                      Print rules and their configuration revision
  rules upsert --file PATH|- --if-revision TIMESTAMP [--before ID|--after ID]
  rules delete --id ID --if-revision TIMESTAMP
  rules move --id ID --before ID|--after ID --if-revision TIMESTAMP

Rule mutations also accept --allow-disruptive. --file - reads JSON from stdin.
Arguments following ctl are independent of desktop/service startup arguments.
--url overrides PITCHPROX_CONTROL_URL and read-only config-file discovery.
Only HTTP loopback origins are accepted; proxies and redirects are disabled.

Config apply requires the unmodified updated_at from config get. Rule mutations
require --if-revision from rules list or config get. Conflicts require a fresh
read and review. Existing rules retain their position unless one is specified.
New rules become the first rule when the list is empty, or go before a final
enabled default catch-all; otherwise a position is required. Rule files
replace the entire rule with that ID, including notes.

Plan first: rule/proxy hot reloads preserve connections; listener/interception
changes can require --allow-disruptive. That flag never overrides a conflict.
Success is JSON on stdout. Failures are JSON on stderr. No writes are retried.
An ambiguous write exits 8: read config get and compare before doing anything.
Configuration exports contain proxy credentials. --help prints this text.
JSON input/output is UTF-8. In Windows PowerShell 5.1, avoid > redirection;
set [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) and
pipe exports to Set-Content -Encoding UTF8 instead.
`

func machineGuide() any {
	textField := func(description string) map[string]any {
		return map[string]any{"type": "string", "description": description}
	}
	intField := func(description string, min, max int) map[string]any {
		return map[string]any{"type": "integer", "minimum": min, "maximum": max, "description": description}
	}
	object := func(properties map[string]any, required ...string) map[string]any {
		out := map[string]any{"type": "object", "additionalProperties": false, "properties": properties}
		if len(required) > 0 {
			out["required"] = required
		}
		return out
	}
	array := func(items any) map[string]any {
		return map[string]any{"type": []string{"array", "null"}, "items": items}
	}
	ruleSchema := object(map[string]any{
		"id":           textField("Stable unique rule ID; required for targeted edits."),
		"name":         textField("Human-readable rule name."),
		"enabled":      map[string]any{"type": "boolean", "description": "Disabled rules do not route traffic; omitted means false."},
		"applications": textField("Semicolon/comma/newline alternatives: executable name, Windows path, * or ? wildcard, numeric PID, Any. Quote paths containing separators. Empty means Any."),
		"target_hosts": textField("Alternatives: hostname, * or ? hostname glob, IP, CIDR, IP range, IP glob, localhost, %ComputerName%, Any. Empty means Any."),
		"target_ports": textField("Alternatives: TCP port 1..65535, inclusive range such as 80-443, or Any. Empty means Any."),
		"action":       map[string]any{"type": "string", "enum": []string{"direct", "proxy", "chain", "block"}, "description": "Defaults to direct; proxy/chain require the corresponding profile ID."},
		"proxy_id":     textField("Required for action=proxy; enabled rules require an enabled profile. Cleared for other actions."),
		"chain_id":     textField("Required for action=chain; enabled rules require an enabled chain. Cleared for other actions."),
		"notes":        textField("Freeform notes; include existing notes when replacing a rule."),
	}, "id")
	proxySchema := object(map[string]any{
		"id": textField("Stable unique proxy profile ID."), "name": textField("Display name."),
		"type":     map[string]any{"type": "string", "enum": []string{"http", "socks5"}},
		"address":  textField("Upstream host:port; bracket IPv6 addresses."),
		"username": textField("Optional upstream username."), "password": textField("Optional upstream password; sensitive."),
		"enabled": map[string]any{"type": "boolean"},
	}, "id", "address")
	chainSchema := object(map[string]any{
		"id": textField("Stable unique chain ID."), "name": textField("Display name."),
		"proxy_ids": array(textField("Proxy ID in traversal order; enabled chains require enabled proxies.")),
		"enabled":   map[string]any{"type": "boolean"},
	}, "id")
	configSchema := object(map[string]any{
		"version":               map[string]any{"type": "integer", "description": "Configuration format version; defaults to 1."},
		"updated_at":            map[string]any{"type": "string", "format": "date-time", "description": "Opaque optimistic revision from config get, preserved when applying edits. Apply rejects zero or missing revision."},
		"retention_minutes":     intField("Connection/rule/traffic history retention; defaults to 7.", 1, 1440),
		"dropped_log_max_bytes": intField("Maximum dropped-connection history size; defaults to 10485760.", 1024, 1<<30),
		"http":                  object(map[string]any{"listen": textField("Loopback host:port, e.g. 127.0.0.1:18080; changing this moves the control listener.")}, "listen"),
		"transparent": object(map[string]any{
			"ipv4_listener":    textField("Transparent IPv4 bind address, e.g. 0.0.0.0."),
			"ipv6_listener":    textField("Transparent IPv6 bind address, e.g. ::."),
			"listener_port":    intField("Transparent listener port.", 1, 65535),
			"sniff_bytes":      intField("Maximum protocol sniff buffer bytes.", 1, 1<<20),
			"sniff_timeout_ms": intField("Protocol sniff timeout in milliseconds.", 1, 60000),
		}, "listener_port", "sniff_bytes", "sniff_timeout_ms"),
		"proxies": array(proxySchema), "chains": array(chainSchema),
		"rules": array(ruleSchema),
	}, "http", "transparent")
	configSchema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	ruleSchema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	example := config.DefaultConfig()
	example.UpdatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return map[string]any{
		"protocol_version": control.ProtocolVersion,
		"encoding":         "JSON is UTF-8 (an optional UTF-8 BOM is accepted). Windows PowerShell 5.1 > redirection writes UTF-16; configure [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) and pipe to Set-Content -Encoding UTF8 instead. Preserve updated_at while editing the exported file.",
		"invocation":       "pitchProx ctl [--url URL] COMMAND",
		"transport":        map[string]any{"http_only": true, "loopback_only": true, "redirects": false, "proxy_environment": false, "timeout_seconds": 30, "max_json_bytes": maxJSONBytes, "write_retries": 0, "required_header": "X-PitchProx-Agent: 1"},
		"discovery_order":  []string{"--url", "PITCHPROX_CONTROL_URL", "existing configuration http.listen (read-only path resolution; PITCHPROX_CONFIG/MYPROX_CONFIG supported)", "http://127.0.0.1:18080 if no config file exists"},
		"commands": []map[string]any{
			{"command": "status", "output": "Status: protocol_version, version, pid, updated_at, listening_address, service_paused, webui_enabled"},
			{"command": "schema", "output": "This machine-readable guide; no network or file writes."},
			{"command": "config get", "output": "Raw live Config; may contain proxy usernames and passwords."},
			{"command": "config validate --file PATH|-", "output": "Raw canonical Config; entirely local; validates rule syntax and references."},
			{"command": "config plan --file PATH|-", "output": "ConfigResult; server preview, no changes, missing revision accepted."},
			{"command": "config apply --file PATH|- [--allow-disruptive]", "output": "ConfigResult; requires config.updated_at from the last read."},
			{"command": "rules list", "output": "{updated_at,rules}"},
			{"command": "rules upsert --file PATH|- --if-revision TIMESTAMP [--before ID|--after ID] [--allow-disruptive]", "output": "ConfigResult; complete replacement of matching ID or insertion of new rule."},
			{"command": "rules delete --id ID --if-revision TIMESTAMP [--allow-disruptive]", "output": "ConfigResult; deletes exactly the matching ID."},
			{"command": "rules move --id ID (--before ID|--after ID) --if-revision TIMESTAMP [--allow-disruptive]", "output": "ConfigResult; preserves all rule fields and moves only its position."},
		},
		"config_schema":  configSchema,
		"rule_schema":    ruleSchema,
		"config_example": example,
		"rule_example":   config.Rule{ID: "deny-example", Name: "Block example", Enabled: true, Applications: "browser.exe", TargetHosts: "*.example.test", TargetPorts: "443", Action: config.ActionBlock},
		"mutation_semantics": map[string]any{
			"revision":          "Use config.updated_at or rules list.updated_at unchanged. Conflicts never retry or merge automatically, and --allow-disruptive never bypasses revision checks.",
			"upsert":            "File is a complete rule replacement, including enabled/action/notes. An existing rule stays in position unless --before or --after is supplied.",
			"new_rule_position": "Without an explicit position, insert as the first rule when the list is empty, or before the final enabled rule with ID default and unconditional application/host/port conditions. Otherwise require --before or --after. Explicit anchors must exist even when the list is empty.",
			"disruption":        "Preview returns plan.mode, runtime_restart, http_rebind, connections_preserved, listening_address, reasons. Runtime restart closes intercepted connections and requires --allow-disruptive; ordinary hot reload affects new connections.",
			"http_rebind":       "Use plan.listening_address/config.http.listen as the origin for subsequent requests after changing the listener.",
			"ambiguous_write":   "Exit 8 means outcome_unknown. Run config get and compare the actual fields/revision; do not automatically repeat the mutation.",
			"result":            "{config,plan,applied,previous_updated_at}; a no-op can return applied=false without advancing revision.",
		},
		"examples": []string{
			"[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); pitchProx ctl config get | Set-Content -Encoding UTF8 config.json",
			"pitchProx ctl config validate --file config.json",
			"pitchProx ctl config plan --file config.json",
			"pitchProx ctl config apply --file config.json",
			"pitchProx ctl rules list",
			"pitchProx ctl rules upsert --file rule.json --if-revision 2026-01-01T00:00:00Z --before default",
			"pitchProx ctl --url http://[::1]:18080 status",
		},
		"exit_codes":  map[string]string{"0": "success", "2": "usage, input, or validation error", "3": "revision conflict", "4": "disruptive change requires opt-in", "5": "instance unavailable or discovery failed", "6": "server upgrade required", "7": "protocol or output error", "8": "mutation outcome unknown; inspect live configuration before retrying"},
		"error_shape": "stderr: {error:{code,message,current_updated_at?}}; stdout is empty on command failure",
	}
}
