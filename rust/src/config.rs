use crate::rules::{Action, Decision, Engine, Rule};
use crate::upstream::{split_host_port, ProxyHop, ProxyKind};
use chrono::{DateTime, FixedOffset, SecondsFormat, TimeDelta, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const DEFAULT_DROPPED_LOG_BYTES: i64 = 10 * 1024 * 1024;
const MIN_DROPPED_LOG_BYTES: i64 = 1024;
const MAX_DROPPED_LOG_BYTES: i64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Revision(DateTime<FixedOffset>);

impl Default for Revision {
    fn default() -> Self {
        Self(DateTime::parse_from_rfc3339("0001-01-01T00:00:00Z").unwrap())
    }
}

impl Revision {
    fn now() -> Self {
        Self(DateTime::<Utc>::from(SystemTime::now()).fixed_offset())
    }
}

impl Serialize for Revision {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut date = self.0.to_rfc3339_opts(SecondsFormat::Nanos, true);
        if let Some(period) = date.find('.') {
            let suffix = period + 10;
            let fraction = date[period + 1..suffix].trim_end_matches('0');
            let tail = if fraction.is_empty() {
                period
            } else {
                period + 1 + fraction.len()
            };
            date.replace_range(tail..suffix, "");
        }
        serializer.serialize_str(&date)
    }
}

impl<'de> Deserialize<'de> for Revision {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let date = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&date)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct Config {
    pub version: i64,
    pub updated_at: Revision,
    pub retention_minutes: i64,
    pub dropped_log_max_bytes: i64,
    pub http: HttpConfig,
    pub transparent: TransparentConfig,
    pub proxies: Option<Vec<ProxyProfile>>,
    #[serde(deserialize_with = "null_default")]
    pub chains: Vec<ProxyChain>,
    pub rules: Option<Vec<RuleConfig>>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct HttpConfig {
    pub listen: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct TransparentConfig {
    pub ipv4_listener: String,
    pub ipv6_listener: String,
    pub listener_port: i64,
    pub sniff_bytes: i64,
    pub sniff_timeout_ms: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct ProxyProfile {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub password: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct ProxyChain {
    pub id: String,
    pub name: String,
    pub proxy_ids: Option<Vec<String>>,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct RuleConfig {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub applications: String,
    pub target_hosts: String,
    pub target_ports: String,
    pub action: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub proxy_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub chain_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

impl Config {
    pub fn fresh() -> Self {
        let default_rule = RuleConfig {
            id: "default".into(),
            name: "Default".into(),
            enabled: true,
            applications: "*".into(),
            target_hosts: "Any".into(),
            target_ports: "Any".into(),
            action: "direct".into(),
            ..RuleConfig::default()
        };
        let localhost = RuleConfig {
            id: "localhost".into(),
            name: "Localhost / This PC".into(),
            target_hosts: "localhost; 127.0.0.1; ::1; %ComputerName%".into(),
            notes: "Bypass loopback and this machine.".into(),
            ..default_rule.clone()
        };
        Self {
            version: 1,
            updated_at: Revision::now(),
            retention_minutes: 7,
            dropped_log_max_bytes: DEFAULT_DROPPED_LOG_BYTES,
            http: HttpConfig {
                listen: "127.0.0.1:18080".into(),
            },
            transparent: TransparentConfig {
                ipv4_listener: "0.0.0.0".into(),
                ipv6_listener: "::".into(),
                listener_port: 26001,
                sniff_bytes: 4096,
                sniff_timeout_ms: 1500,
            },
            proxies: None,
            chains: Vec::new(),
            rules: Some(vec![localhost, default_rule]),
        }
    }

    pub fn canonicalize(mut self) -> Result<Self, String> {
        self.normalize();
        self.validate()?;
        Ok(self)
    }

    pub fn compile(&self, computer_name: &str) -> Result<Engine, String> {
        let rules = self
            .rules
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|r| {
                let action = r.parse_action()?;
                Ok(Rule {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    enabled: r.enabled,
                    applications: r.applications.clone(),
                    target_hosts: r.target_hosts.clone(),
                    target_ports: r.target_ports.clone(),
                    action,
                    proxy_id: r.proxy_id.clone(),
                    chain_id: r.chain_id.clone(),
                })
            })
            .collect::<Result<_, String>>()?;
        Engine::compile(rules, computer_name)
    }

    pub fn upstream_hops(&self, decision: Decision<'_>) -> Result<Vec<ProxyHop<'_>>, String> {
        let Some(rule) = decision.rule else {
            return Ok(Vec::new());
        };
        match rule.action {
            Action::Direct => Ok(Vec::new()),
            Action::Block => Err("unsupported action \"block\"".into()),
            Action::Proxy => Ok(vec![self
                .enabled_proxy(&rule.proxy_id)
                .ok_or_else(|| format!("unknown proxy {:?}", rule.proxy_id))?
                .hop()?]),
            Action::Chain => {
                let chain = self
                    .chains
                    .iter()
                    .find(|chain| chain.enabled && chain.id == rule.chain_id)
                    .ok_or_else(|| format!("unknown chain {:?}", rule.chain_id))?;
                chain
                    .proxy_ids
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(|id| {
                        self.enabled_proxy(id)
                            .ok_or_else(|| {
                                format!("chain {:?} references unknown proxy {id:?}", chain.name)
                            })?
                            .hop()
                    })
                    .collect()
            }
        }
    }

    fn enabled_proxy(&self, id: &str) -> Option<&ProxyProfile> {
        self.proxies
            .as_deref()?
            .iter()
            .find(|proxy| proxy.enabled && proxy.id == id)
    }

    fn normalize(&mut self) {
        if self.version == 0 {
            self.version = 1;
        }
        if self.retention_minutes <= 0 {
            self.retention_minutes = 7;
        }
        if self.dropped_log_max_bytes <= 0 {
            self.dropped_log_max_bytes = DEFAULT_DROPPED_LOG_BYTES;
        }
        trim(&mut self.http.listen);
        trim(&mut self.transparent.ipv4_listener);
        trim(&mut self.transparent.ipv6_listener);

        normalize_list(&mut self.proxies, |proxy| {
            for field in [
                &mut proxy.id,
                &mut proxy.name,
                &mut proxy.address,
                &mut proxy.username,
            ] {
                trim(field);
            }
            let kind = proxy.kind.trim().to_lowercase();
            proxy.kind = match kind.as_str() {
                "" | "http" | "http connect" | "http_connect" | "connect" => "http".into(),
                "socks" | "socks5" | "socks v5" => "socks5".into(),
                _ => kind,
            };
        });
        for chain in &mut self.chains {
            trim(&mut chain.id);
            trim(&mut chain.name);
            normalize_list(&mut chain.proxy_ids, trim);
        }
        normalize_list(&mut self.rules, |rule| {
            for field in [
                &mut rule.id,
                &mut rule.name,
                &mut rule.applications,
                &mut rule.target_hosts,
                &mut rule.target_ports,
                &mut rule.proxy_id,
                &mut rule.chain_id,
                &mut rule.notes,
            ] {
                trim(field);
            }
            rule.action = rule.action.trim().to_lowercase();
            if rule.action.is_empty() {
                rule.action = "direct".into();
            }
            match rule.action.as_str() {
                "proxy" => rule.chain_id.clear(),
                "chain" => rule.proxy_id.clear(),
                "direct" | "block" => {
                    rule.proxy_id.clear();
                    rule.chain_id.clear();
                }
                _ => {}
            }
        });
    }

    fn validate(&self) -> Result<(), String> {
        if self.http.listen.is_empty() {
            return Err("http.listen is required".into());
        }
        let (host, port) =
            split_host_port(&self.http.listen).ok_or("http.listen must be host:port")?;
        if !is_loopback_host(host) {
            return Err("http.listen must use a loopback host".into());
        }
        if !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<std::num::NonZeroU16>().is_err()
        {
            return Err("http.listen port must be numeric and in 1..65535".into());
        }
        for (field, value, min, max) in [
            (
                "transparent.listener_port",
                self.transparent.listener_port,
                1,
                65535,
            ),
            (
                "transparent.sniff_bytes",
                self.transparent.sniff_bytes,
                1,
                1048576,
            ),
            (
                "transparent.sniff_timeout_ms",
                self.transparent.sniff_timeout_ms,
                1,
                60000,
            ),
            ("retention_minutes", self.retention_minutes, 1, 1440),
            (
                "dropped_log_max_bytes",
                self.dropped_log_max_bytes,
                MIN_DROPPED_LOG_BYTES,
                MAX_DROPPED_LOG_BYTES,
            ),
        ] {
            if !(min..=max).contains(&value) {
                return Err(format!("{field} must be in {min}..{max}"));
            }
        }
        let mut proxies = HashMap::new();
        for proxy in self.proxies.as_deref().unwrap_or_default() {
            if proxy.id.is_empty() {
                return Err("proxy id is required".into());
            }
            if proxies.insert(proxy.id.as_str(), proxy.enabled).is_some() {
                return Err(format!("duplicate proxy id {:?}", proxy.id));
            }
            let label = label(&proxy.name, &proxy.id);
            if !matches!(proxy.kind.as_str(), "http" | "socks5") {
                return Err(format!(
                    "proxy {label:?} has unsupported type {:?}",
                    proxy.kind
                ));
            }
            if proxy.address.is_empty() {
                return Err(format!("proxy {label:?} address is required"));
            }
            if split_host_port(&proxy.address).is_none() {
                return Err(format!("proxy {label:?} address must be host:port"));
            }
        }
        let mut chains = HashMap::new();
        for chain in &self.chains {
            if chain.id.is_empty() {
                return Err("chain id is required".into());
            }
            if chains.insert(chain.id.as_str(), chain.enabled).is_some() {
                return Err(format!("duplicate chain id {:?}", chain.id));
            }
            let label = label(&chain.name, &chain.id);
            let members = chain.proxy_ids.as_deref().unwrap_or_default();
            if chain.enabled && members.is_empty() {
                return Err(format!(
                    "enabled chain {label:?} must contain at least one proxy"
                ));
            }
            for member in members {
                match proxies.get(member.as_str()) {
                    None => {
                        return Err(format!(
                            "chain {label:?} references unknown proxy {member:?}"
                        ))
                    }
                    Some(false) if chain.enabled => {
                        return Err(format!(
                            "enabled chain {label:?} references disabled proxy {member:?}"
                        ))
                    }
                    _ => {}
                }
            }
        }
        let mut ids = HashSet::new();
        for rule in self.rules.as_deref().unwrap_or_default() {
            if rule.id.is_empty() {
                return Err("rule id is required".into());
            }
            if !ids.insert(&rule.id) {
                return Err(format!("duplicate rule id {:?}", rule.id));
            }
            let label = label(&rule.name, &rule.id);
            let (kind, id, enabled) = match rule.parse_action()? {
                Action::Proxy => ("proxy", &rule.proxy_id, &proxies),
                Action::Chain => ("chain", &rule.chain_id, &chains),
                Action::Direct | Action::Block => continue,
            };
            if id.is_empty() {
                return Err(format!(
                    "rule {label:?} uses action={kind} but {kind}_id is empty"
                ));
            }
            if rule.enabled && enabled.get(id.as_str()) != Some(&true) {
                return Err(format!(
                    "enabled rule {label:?} references unknown or disabled {kind} {id:?}"
                ));
            }
        }
        Ok(())
    }
}

impl RuleConfig {
    fn parse_action(&self) -> Result<Action, String> {
        Ok(match self.action.as_str() {
            "direct" => Action::Direct,
            "proxy" => Action::Proxy,
            "chain" => Action::Chain,
            "block" => Action::Block,
            _ => {
                return Err(format!(
                    "rule {:?} has unsupported action {:?}",
                    label(&self.name, &self.id),
                    self.action
                ))
            }
        })
    }
}

impl ProxyProfile {
    fn hop(&self) -> Result<ProxyHop<'_>, String> {
        let kind = match self.kind.as_str() {
            "http" => ProxyKind::HttpConnect,
            "socks5" => ProxyKind::Socks5,
            _ => return Err(format!("unsupported proxy type {:?}", self.kind)),
        };
        Ok(ProxyHop {
            kind,
            address: &self.address,
            username: &self.username,
            password: &self.password,
        })
    }
}

pub struct Store {
    path: PathBuf,
    config: Config,
}

impl Store {
    pub fn load_or_create(path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("create config dir: {err}"))?;
        }
        let mut config = match fs::read(&path) {
            Ok(bytes) => parse_legacy_config(&bytes)?
                .canonicalize()
                .map_err(|err| format!("validate config: {err}"))?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let config = Config::fresh();
                save_to(&path, &config)?;
                config
            }
            Err(err) => return Err(format!("read config: {err}")),
        };
        if config.updated_at == Revision::default() {
            config.updated_at = Revision::now();
            save_to(&path, &config)?;
        }
        Ok(Self { path, config })
    }

    pub fn current(&self) -> &Config {
        &self.config
    }

    pub fn save(&mut self, config: Config) -> Result<&Config, String> {
        let mut config = config.canonicalize()?;
        let now = Revision::now();
        config.updated_at = if now > self.config.updated_at {
            now
        } else {
            Revision(
                self.config
                    .updated_at
                    .0
                    .with_timezone(&Utc)
                    .checked_add_signed(TimeDelta::nanoseconds(1))
                    .ok_or("configuration revision overflow")?
                    .fixed_offset(),
            )
        };
        save_to(&self.path, &config)?;
        self.config = config;
        Ok(&self.config)
    }
}

pub(crate) fn parse_legacy_config(bytes: &[u8]) -> Result<Config, String> {
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let mut document: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|err| format!("parse config: {err}"))?;
    // Go accepts null for legacy scalar fields and treats it as missing.
    strip_legacy_nulls(&mut document);
    serde_json::from_value(document).map_err(|err| format!("parse config: {err}"))
}

fn strip_legacy_nulls(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => {
            fields.retain(|_, value| !value.is_null());
            fields.values_mut().for_each(strip_legacy_nulls);
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(strip_legacy_nulls),
        _ => {}
    }
}

fn save_to(path: &Path, config: &Config) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(config).map_err(|err| format!("marshal config: {err}"))?;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    fs::write(&temporary, data).map_err(|err| format!("write tmp config: {err}"))?;
    fs::rename(temporary, path).map_err(|err| format!("replace config: {err}"))
}

fn trim(value: &mut String) {
    if value.trim() != value {
        *value = value.trim().to_owned();
    }
}

fn label<'a>(name: &'a str, id: &'a str) -> &'a str {
    if name.is_empty() {
        id
    } else {
        name
    }
}

fn normalize_list<T>(list: &mut Option<Vec<T>>, normalize: impl FnMut(&mut T)) {
    if let Some(values) = list {
        if values.is_empty() {
            *list = None;
        } else {
            values.iter_mut().for_each(normalize);
        }
    }
}

fn null_default<'de, T: Deserialize<'de> + Default, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']).trim();
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(IpAddr::V6(ip)) => {
            ip == Ipv6Addr::LOCALHOST || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
        Err(_) => false,
    }
}
