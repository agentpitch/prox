use crate::app::config_path;
use crate::config::{Config, Revision, RuleConfig};
use crate::localhttp;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::time::Duration;

const PREFIX: &str = "/api/control/agent/";
const LIMIT: u64 = 8 << 20;

#[derive(Debug, Serialize, Deserialize)]
struct Error {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_updated_at: Option<Revision>,
    #[serde(skip)]
    exit: i32,
}
fn failure(code: &str, message: impl Into<String>, exit: i32) -> Error {
    Error {
        code: code.into(),
        message: message.into(),
        current_updated_at: None,
        exit,
    }
}
fn usage(message: impl Into<String>) -> Error {
    failure("usage_error", message, 2)
}

enum Output {
    Text(&'static str),
    Json(Value),
}

pub fn run(args: &[String]) -> i32 {
    let result = execute(args, &mut io::stdin().lock());
    match result {
        Ok(output) => {
            let output = match output {
                Output::Text(text) => text.to_owned(),
                Output::Json(value) => {
                    format!("{}\n", serde_json::to_string_pretty(&value).unwrap())
                }
            };
            if io::stdout().lock().write_all(output.as_bytes()).is_ok() {
                0
            } else {
                report(failure("output_error", "cannot write control output", 7))
            }
        }
        Err(err) => report(err),
    }
}
fn report(error: Error) -> i32 {
    let body = serde_json::to_string(&json!({"error":error})).unwrap();
    let _ = writeln!(io::stderr().lock(), "{body}");
    error.exit
}

struct Invocation<'a> {
    command: String,
    flags: BTreeMap<&'a str, &'a str>,
}
impl<'a> Invocation<'a> {
    fn flag(&self, flag: &str) -> &'a str {
        self.flags.get(flag).copied().unwrap_or_default()
    }
}

fn parse(args: &[String]) -> Result<Invocation<'_>, Error> {
    let mut inv = Invocation {
        command: String::new(),
        flags: BTreeMap::new(),
    };
    let mut words = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if matches!(arg.as_str(), "--help" | "-h") {
            return Ok(Invocation {
                command: "help".into(),
                flags: BTreeMap::new(),
            });
        }
        if !arg.starts_with('-') {
            words.push(arg.as_str());
            continue;
        }
        let name = arg
            .strip_prefix("--")
            .ok_or_else(|| usage(format!("unknown option {arg}")))?;
        let (key, value) = name
            .split_once('=')
            .map_or((name, None), |(k, v)| (k, Some(v)));
        let value = match key {
            "url" | "file" | "id" | "if-revision" | "before" | "after" => match value {
                Some(v) => v,
                None => iter
                    .next()
                    .filter(|arg| !arg.starts_with("--"))
                    .ok_or_else(|| usage(format!("--{key} requires a value")))?,
            },
            "allow-disruptive" => match value {
                None | Some("true") => "true",
                Some("false") => "false",
                _ => return Err(usage("--allow-disruptive accepts true or false")),
            },
            _ => return Err(usage(format!("unknown option --{key}"))),
        };
        if value.is_empty() {
            return Err(usage(format!("--{key} requires a nonempty value")));
        }
        if inv.flags.insert(key, value).is_some() {
            return Err(usage(format!("duplicate option --{key}")));
        }
    }
    inv.command = words.join(" ");
    let (allowed, required) = match inv.command.as_str() {
        "help" | "schema" | "status" | "config get" | "rules list" => (&[][..], &[][..]),
        "config validate" | "config plan" => (&["file"][..], &["file"][..]),
        "config apply" => (&["file", "allow-disruptive"][..], &["file"][..]),
        "rules upsert" => (
            &["file", "if-revision", "before", "after", "allow-disruptive"][..],
            &["file", "if-revision"][..],
        ),
        "rules delete" => (
            &["id", "if-revision", "allow-disruptive"][..],
            &["id", "if-revision"][..],
        ),
        "rules move" => (
            &["id", "if-revision", "before", "after", "allow-disruptive"][..],
            &["id", "if-revision"][..],
        ),
        _ => {
            return Err(usage(
                "expected a control command; use pitchProx ctl --help",
            ))
        }
    };
    for key in inv.flags.keys() {
        if *key != "url" && !allowed.contains(key) {
            return Err(usage(format!("--{key} is not valid for {}", inv.command)));
        }
    }
    for key in required {
        if inv.flag(key).is_empty() {
            return Err(usage(format!("--{key} is required")));
        }
    }
    let (before, after) = (
        !inv.flag("before").is_empty(),
        !inv.flag("after").is_empty(),
    );
    if before && after {
        return Err(usage("choose either --before or --after"));
    }
    if inv.command == "rules move" && !before && !after {
        return Err(usage("rules move requires --before or --after"));
    }
    Ok(inv)
}

fn execute(args: &[String], stdin: &mut impl Read) -> Result<Output, Error> {
    let inv = parse(args)?;
    match inv.command.as_str() {
        "help" => return Ok(Output::Text(include_str!("ctl-help.txt"))),
        "schema" => return Ok(Output::Text(include_str!("ctl-schema.json"))),
        _ => {}
    }
    let mut candidate = None;
    if matches!(
        inv.command.as_str(),
        "config validate" | "config plan" | "config apply"
    ) {
        let data = input(inv.flag("file"), stdin)?;
        let value: Value = documents(&data)?;
        crate::http::strict_config(&value).map_err(|e| failure("invalid_json", e, 2))?;
        let cfg = validate(documents(&data)?)?;
        if inv.command == "config validate" {
            return Ok(Output::Json(json!(cfg)));
        }
        if inv.command == "config apply" && cfg.updated_at == Revision::default() {
            return Err(failure("revision_required","config.updated_at is required; fetch config get before planning or applying changes",2));
        }
        candidate = Some(cfg);
    }
    let revision = if inv.flag("if-revision").is_empty() {
        Revision::default()
    } else {
        serde_json::from_value::<Revision>(json!(inv.flag("if-revision")))
            .ok()
            .filter(|r| *r != Revision::default())
            .ok_or_else(|| usage("--if-revision must be a nonzero RFC3339 timestamp"))?
    };
    let mut rule = RuleConfig::default();
    if inv.command == "rules upsert" {
        let input = input(inv.flag("file"), stdin)?;
        let raw: Value = documents(&input)?;
        crate::http::strict_config(&json!({"rules":[raw]}))
            .map_err(|e| failure("invalid_json", e, 2))?;
        rule = documents(&input)?;
        rule.id = rule.id.trim().to_owned();
        if rule.id.is_empty() {
            return Err(failure("validation_error", "rule.id is required", 2));
        }
    }
    let url = discover(inv.flag("url"))?;
    let allow = inv.flag("allow-disruptive") == "true";
    let value = match inv.command.as_str() {
        "status" => {
            let response = request(&url, "GET", "status", None, false)?;
            if response["protocol_version"] != 1 {
                return Err(failure(
                    "protocol_error",
                    "unsupported or missing agent protocol version",
                    7,
                ));
            }
            response
        }
        "config get" => json!(get_config(&url)?),
        "config apply" | "config plan" => save(
            &url,
            candidate.unwrap(),
            inv.command == "config plan",
            allow,
        )?,
        "rules list" => {
            let config = get_config(&url)?;
            json!({"updated_at":config.updated_at,"rules":config.rules})
        }
        _ => {
            let current = get_config(&url)?;
            if current.updated_at != revision {
                let mut err = failure(
                    "revision_conflict",
                    "configuration changed; fetch config get and review changes before retrying",
                    3,
                );
                err.current_updated_at = Some(current.updated_at);
                return Err(err);
            }
            save(&url, validate(mutate(current, &inv, rule)?)?, false, allow)?
        }
    };
    Ok(Output::Json(value))
}

fn validate(value: Config) -> Result<Config, Error> {
    let value = value
        .canonicalize()
        .map_err(|e| failure("validation_error", e, 2))?;
    value
        .compile("")
        .map_err(|e| failure("validation_error", e, 2))?;
    Ok(value)
}

fn mutate(mut config: Config, inv: &Invocation<'_>, mut rule: RuleConfig) -> Result<Config, Error> {
    let id = if inv.command == "rules upsert" {
        rule.id.clone()
    } else {
        inv.flag("id").into()
    };
    let rules = config.rules.get_or_insert_with(Vec::new);
    let position = rules.iter().position(|rule| rule.id == id);
    if position.is_none() && inv.command != "rules upsert" {
        return Err(failure(
            "rule_not_found",
            format!("rule id not found: {id}"),
            2,
        ));
    }
    let (before, after) = (inv.flag("before"), inv.flag("after"));
    if before == id || after == id {
        return Err(failure(
            "validation_error",
            "a rule cannot be positioned relative to itself",
            2,
        ));
    }
    if inv.command == "rules delete" {
        rules.remove(position.unwrap());
        return Ok(config);
    }
    if let Some(index) = position {
        if before.is_empty() && after.is_empty() {
            rules[index] = rule;
            return Ok(config);
        }
        let old = rules.remove(index);
        if inv.command == "rules move" {
            rule = old;
        }
    }
    let at = if !before.is_empty() || !after.is_empty() {
        rules
            .iter()
            .enumerate()
            .find_map(|(i, rule)| {
                if rule.id == before {
                    Some(i)
                } else if rule.id == after {
                    Some(i + 1)
                } else {
                    None
                }
            })
            .ok_or_else(|| failure("rule_not_found", "position anchor rule not found", 2))?
    } else if rules.is_empty() {
        0
    } else if rules.last().is_some_and(default_catchall) {
        rules.len() - 1
    } else {
        return Err(failure("position_required","new rules require --before or --after when there is no final enabled default catch-all",2));
    };
    rules.insert(at, rule);
    Ok(config)
}
fn default_catchall(rule: &RuleConfig) -> bool {
    let any = |s: &str| s.trim().is_empty() || s.trim().eq_ignore_ascii_case("any");
    rule.id == "default"
        && rule.enabled
        && (any(&rule.applications) || rule.applications.trim() == "*")
        && any(&rule.target_hosts)
        && any(&rule.target_ports)
}
fn input(path: &str, stdin: &mut impl Read) -> Result<Vec<u8>, Error> {
    let mut data = Vec::new();
    if path == "-" {
        stdin.take(LIMIT + 1).read_to_end(&mut data)
    } else {
        std::fs::File::open(path).and_then(|file| file.take(LIMIT + 1).read_to_end(&mut data))
    }
    .map_err(|e| failure("input_error", e.to_string(), 2))?;
    if data.len() as u64 > LIMIT {
        return Err(failure("input_error", "request exceeds JSON size limit", 2));
    }
    Ok(data)
}
fn documents<T: serde::de::DeserializeOwned>(input: &[u8]) -> Result<T, Error> {
    let input = input.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(input);
    if std::str::from_utf8(input).is_err() {
        return Err(failure("invalid_json", "JSON must be valid UTF-8", 2));
    }
    serde_json::from_slice(input).map_err(|e| failure("invalid_json", e.to_string(), 2))
}

fn discover(explicit: &str) -> Result<String, Error> {
    let url = if !explicit.is_empty() {
        explicit.into()
    } else if let Ok(environment) = std::env::var("PITCHPROX_CONTROL_URL") {
        if !environment.trim().is_empty() {
            environment
        } else {
            discovery_file()?
        }
    } else {
        discovery_file()?
    };
    localhttp::normalize(&url).map_err(|e| failure("discovery_error", e, 5))
}
fn discovery_file() -> Result<String, Error> {
    let file = std::fs::File::open(config_path(false));
    match file {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok("http://127.0.0.1:18080".into()),
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| failure("discovery_error", e.to_string(), 5))?;
            let document =
                documents::<Value>(&bytes).map_err(|e| failure("discovery_error", e.message, 5))?;
            let addr = document["http"]["listen"]
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| failure("discovery_error", "http.listen is required", 5))?;
            Ok(format!("http://{}", addr.trim()))
        }
        Err(err) => Err(failure("discovery_error", err.to_string(), 5)),
    }
}
fn request(
    url: &str,
    method: &str,
    endpoint: &str,
    payload: Option<Value>,
    mutation: bool,
) -> Result<Value, Error> {
    let data = payload
        .map(|v| serde_json::to_vec(&v).unwrap())
        .unwrap_or_default();
    if data.len() as u64 > LIMIT {
        return Err(failure("input_error", "request exceeds JSON size limit", 2));
    }
    let (status, body) = localhttp::request(
        url,
        method,
        &format!("{PREFIX}{endpoint}"),
        &data,
        true,
        Duration::from_secs(30),
    )
    .map_err(|e| transport(e.to_string(), mutation))?;
    if status == 404 {
        return Err(failure(
            "upgrade_required",
            "server does not support agent control; upgrade the running pitchProx instance",
            6,
        ));
    }
    if (300..400).contains(&status) {
        return Err(failure(
            "protocol_error",
            "control server redirects are refused",
            7,
        ));
    }
    let response = serde_json::from_slice::<Value>(&body);
    if !(200..300).contains(&status) {
        if let Ok(value) = response {
            if let Ok(mut error) = serde_json::from_value::<Error>(value["error"].clone()) {
                error.exit = error_exit(&error.code, status);
                return Err(error);
            }
        }
        return Err(failure(
            "protocol_error",
            format!("control server returned HTTP {status} without a typed JSON error"),
            7,
        ));
    }
    response.map_err(|_| {
        if mutation {
            transport("control server returned invalid JSON", true)
        } else {
            failure("protocol_error", "control server returned invalid JSON", 7)
        }
    })
}
fn transport(message: impl std::fmt::Display, mutation: bool) -> Error {
    if mutation {
        failure("outcome_unknown",format!("configuration write was not confirmed: {message}; do not retry automatically; run config get and compare the resulting configuration"),8)
    } else {
        failure(
            "unavailable",
            format!("control request failed: {message}"),
            5,
        )
    }
}
fn error_exit(code: &str, status: u16) -> i32 {
    match code {
        "revision_conflict" | "config_conflict" => 3,
        "disruptive_change" | "disruptive_change_required" | "disruptive_confirmation_required" => {
            4
        }
        "validation_error" | "invalid_config" | "invalid_request" | "revision_required" => 2,
        "unavailable" | "update_busy" | "activation_failed" | "forbidden" => 5,
        _ if matches!(status, 409 | 412) => 3,
        _ if matches!(status, 400 | 422) => 2,
        _ => 7,
    }
}
fn get_config(url: &str) -> Result<Config, Error> {
    let value = request(url, "GET", "config", None, false)?;
    let error = || {
        failure(
            "protocol_error",
            "server configuration response is not a supported configuration with updated_at",
            7,
        )
    };
    crate::http::strict_config(&value).map_err(|_| error())?;
    serde_json::from_value::<Config>(value)
        .ok()
        .filter(|config| config.updated_at != Revision::default())
        .ok_or_else(error)
}
fn save(url: &str, config: Config, dry: bool, allow: bool) -> Result<Value, Error> {
    let mutation = !dry;
    let expected = config.updated_at;
    let data = request(
        url,
        if dry { "POST" } else { "PUT" },
        if dry { "config/validate" } else { "config" },
        Some(json!({
            "config":config,"expected_updated_at":expected,"dry_run":dry,"allow_disruptive":allow
        })),
        mutation,
    )?;
    let check = (|| {
        let previous = serde_json::from_value::<Revision>(data["previous_updated_at"].clone())
            .map_err(|_| "missing or mismatched previous_updated_at")?;
        if previous == Revision::default()
            || expected != Revision::default() && previous != expected
        {
            return Err("missing or mismatched previous_updated_at");
        }
        let actual = serde_json::from_value::<Config>(data["config"].clone())
            .map_err(|_| "invalid returned config")?;
        validate(actual.clone()).map_err(|_| "invalid returned config")?;
        let plan = &data["plan"];
        let preserved = plan["connections_preserved"].as_bool();
        let restarted = plan["runtime_restart"].as_bool();
        let rebound = plan["http_rebind"].as_bool();
        if plan["listening_address"] != actual.http.listen
            || preserved.is_none()
            || restarted.is_none()
            || preserved == restarted
        {
            return Err("missing or inconsistent activation plan");
        }
        let noop = match (plan["mode"].as_str(), restarted, rebound) {
            (Some("no_change"), Some(false), Some(false)) => true,
            (Some("hot_reload"), Some(false), Some(false))
            | (Some("listener_rebind"), Some(false), Some(true))
            | (Some("runtime_restart"), Some(true), Some(_)) => false,
            _ => return Err("unsupported or missing activation mode"),
        };
        let applied = data["applied"].as_bool().ok_or("missing applied field")?;
        if dry {
            if applied {
                return Err("preview unexpectedly reports a write");
            }
        } else if applied && (noop || actual.updated_at <= previous) {
            return Err("write did not advance the revision");
        } else if !applied && (!noop || actual.updated_at != previous) {
            return Err("unconfirmed write without a no-change plan");
        }
        Ok(())
    })();
    check.map_err(|e| {
        if mutation {
            transport(format!("invalid configuration result: {e}"), true)
        } else {
            failure(
                "protocol_error",
                format!("invalid configuration preview: {e}"),
                7,
            )
        }
    })?;
    Ok(data)
}
