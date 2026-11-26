use std::borrow::Cow;
use std::net::IpAddr;
use std::ops::Range;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Action {
    #[default]
    Direct,
    Proxy,
    Chain,
    Block,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub applications: String,
    pub target_hosts: String,
    pub target_ports: String,
    pub action: Action,
    pub proxy_id: String,
    pub chain_id: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Request<'a> {
    pub pid: u32,
    pub app_path: &'a str,
    pub hostname: &'a str,
    pub target_ip: Option<IpAddr>,
    pub target_ip_zone: &'a str,
    pub target_port: u16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MatchDetails<'a> {
    pub application: &'a str,
    pub host: &'a str,
    pub port: &'a str,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Decision<'a> {
    pub rule: Option<&'a Rule>,
    pub conditions: MatchDetails<'a>,
}

impl Decision<'_> {
    pub fn action(self) -> Action {
        self.rule.map_or(Action::Direct, |rule| rule.action)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preflight<'a> {
    pub decision: Decision<'a>,
    pub definitive: bool,
    pub match_definitive: bool,
    pub needs_hostname: bool,
}

struct PreparedRequest<'a> {
    request: Request<'a>,
    app_path: Option<(Cow<'a, str>, Range<usize>)>,
    hostname: Option<Cow<'a, str>>,
    ip_text: Option<String>,
}

impl<'a> PreparedRequest<'a> {
    fn new(request: Request<'a>) -> Self {
        Self {
            request,
            app_path: None,
            hostname: None,
            ip_text: None,
        }
    }

    fn application(&mut self, full_path: bool) -> &str {
        let (path, basename) = self.app_path.get_or_insert_with(|| {
            let path = self.request.app_path.trim();
            let path = if path.contains('/') {
                Cow::Owned(lowercase(&path.replace('/', "\\")).into_owned())
            } else {
                lowercase(path)
            };
            let base_path = path.trim_end_matches('\\');
            let start = base_path.rfind('\\').map_or(0, |i| i + 1);
            let basename = start..base_path.len();
            (path, basename)
        });
        if full_path {
            path
        } else {
            &path[basename.clone()]
        }
    }

    fn hostname(&mut self) -> &str {
        self.hostname
            .get_or_insert_with(|| lowercase(self.request.hostname.trim()))
    }

    fn ip_text(&mut self, ip: IpAddr) -> &str {
        self.ip_text.get_or_insert_with(|| {
            let mut text = ip.to_string();
            if !self.request.target_ip_zone.is_empty() {
                text.push('%');
                text.push_str(&lowercase(self.request.target_ip_zone));
            }
            text
        })
    }
}

#[derive(Debug)]
enum Alternatives<T> {
    Any(&'static str),
    List(Vec<T>),
}

#[derive(Debug)]
enum AppMatcher {
    Pid(u32),
    Executable { full_path: bool, glob: bool },
}

#[derive(Debug)]
enum HostMatcher {
    ComputerName,
    Name,
    NameGlob,
    Address(IpAddr, String),
    Prefix(IpAddr, u32),
    Range(IpAddr, IpAddr),
    AddressGlob,
}

impl HostMatcher {
    fn needs_hostname(&self) -> bool {
        matches!(self, Self::ComputerName | Self::Name | Self::NameGlob)
    }
}

#[derive(Debug)]
struct Pattern<T> {
    label: String,
    matcher: T,
}

type PortRange = std::ops::RangeInclusive<u16>;

#[derive(Debug)]
struct CompiledRule {
    rule: Rule,
    applications: Alternatives<Pattern<AppMatcher>>,
    hosts: Alternatives<Pattern<HostMatcher>>,
    ports: Alternatives<Pattern<PortRange>>,
    hostname_dependent: bool,
}

impl CompiledRule {
    fn compile(rule: Rule) -> Result<Self, String> {
        let error_at = |field, error: &str| format!("rule {:?} {field}: {error}", rule.name);
        let applications = parse_applications(
            split_field(&rule.applications).map_err(|err| error_at("applications", err))?,
        );
        let hosts = parse_hosts(
            split_field(&rule.target_hosts).map_err(|err| error_at("target hosts", err))?,
        );
        let ports = split_field(&rule.target_ports).map_err(|err| error_at("target ports", err))?;
        let ports = parse_ports(ports).map_err(|err| error_at("target ports", &err))?;
        let hostname_dependent = match &hosts {
            Alternatives::Any(_) => false,
            Alternatives::List(patterns) => patterns.iter().any(|p| p.matcher.needs_hostname()),
        };
        Ok(Self {
            rule,
            applications,
            hosts,
            ports,
            hostname_dependent,
        })
    }

    fn match_application(&self, request: &mut PreparedRequest<'_>) -> Option<&str> {
        let Alternatives::List(patterns) = &self.applications else {
            return self.applications.any_label();
        };
        patterns.iter().find_map(|p| {
            let matched = match p.matcher {
                AppMatcher::Pid(pid) => request.request.pid == pid,
                AppMatcher::Executable { full_path, glob } => {
                    let application = request.application(full_path);
                    if glob {
                        wildcard_match(&p.label, application)
                    } else {
                        p.label == application
                    }
                }
            };
            matched.then_some(p.label.as_str())
        })
    }

    fn match_host(&self, request: &mut PreparedRequest<'_>, computer_name: &str) -> Option<&str> {
        let Alternatives::List(patterns) = &self.hosts else {
            return self.hosts.any_label();
        };
        for p in patterns {
            let matched = match &p.matcher {
                HostMatcher::ComputerName => {
                    let hostname = request.hostname();
                    !hostname.is_empty() && hostname == computer_name
                }
                HostMatcher::Name => request.hostname() == p.label,
                HostMatcher::NameGlob => {
                    let hostname = request.hostname();
                    !hostname.is_empty() && wildcard_match(&p.label, hostname)
                }
                HostMatcher::Address(ip, zone) => {
                    request.request.target_ip == Some(*ip) && request.request.target_ip_zone == zone
                }
                HostMatcher::Prefix(network, bits) => request.request.target_ip.is_some_and(|ip| {
                    request.request.target_ip_zone.is_empty()
                        && prefix_contains(*network, *bits, ip)
                }),
                HostMatcher::Range(start, end) => request.request.target_ip.is_some_and(|ip| {
                    ip_bytes(*start) <= ip_bytes(ip) && ip_bytes(ip) <= ip_bytes(*end)
                }),
                HostMatcher::AddressGlob => request
                    .request
                    .target_ip
                    .is_some_and(|ip| wildcard_match(&p.label, request.ip_text(ip))),
            };
            if matched {
                return Some(&p.label);
            }
        }
        None
    }

    fn match_port(&self, port: u16) -> Option<&str> {
        match &self.ports {
            Alternatives::Any(label) => Some(label),
            Alternatives::List(patterns) => patterns
                .iter()
                .find(|p| p.matcher.contains(&port))
                .map(|p| p.label.as_str()),
        }
    }

    fn decision<'a>(&'a self, application: &'a str, host: &'a str, port: &'a str) -> Decision<'a> {
        Decision {
            rule: Some(&self.rule),
            conditions: MatchDetails {
                application,
                host,
                port,
            },
        }
    }
}

impl<T> Alternatives<T> {
    fn any_label(&self) -> Option<&'static str> {
        match self {
            Self::Any(label) => Some(label),
            Self::List(_) => None,
        }
    }
}

#[derive(Debug)]
pub struct Engine {
    rules: Vec<CompiledRule>,
    computer_name: String,
    all_enabled_direct: bool,
}

impl Engine {
    pub fn compile(rules: Vec<Rule>, computer_name: &str) -> Result<Self, String> {
        let all_enabled_direct = rules
            .iter()
            .all(|r| !r.enabled || r.action == Action::Direct);
        Ok(Self {
            rules: rules
                .into_iter()
                .map(CompiledRule::compile)
                .collect::<Result<_, _>>()?,
            computer_name: lowercase(computer_name.trim()).into_owned(),
            all_enabled_direct,
        })
    }

    pub fn all_enabled_direct(&self) -> bool {
        self.all_enabled_direct
    }

    pub fn decide(&self, request: Request<'_>) -> Decision<'_> {
        let mut request = PreparedRequest::new(request);
        for rule in self.rules.iter().filter(|r| r.rule.enabled) {
            let Some(application) = rule.match_application(&mut request) else {
                continue;
            };
            let Some(host) = rule.match_host(&mut request, &self.computer_name) else {
                continue;
            };
            let Some(port) = rule.match_port(request.request.target_port) else {
                continue;
            };
            return rule.decision(application, host, port);
        }
        Decision::default()
    }

    pub fn preflight(&self, request: Request<'_>) -> Preflight<'_> {
        let mut request = PreparedRequest::new(request);
        for (index, rule) in self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.rule.enabled)
        {
            let Some(application) = rule.match_application(&mut request) else {
                continue;
            };
            let Some(port) = rule.match_port(request.request.target_port) else {
                continue;
            };
            if let Some(host) = rule.match_host(&mut request, &self.computer_name) {
                return Preflight {
                    decision: rule.decision(application, host, port),
                    definitive: true,
                    match_definitive: true,
                    needs_hostname: false,
                };
            }
            if !rule.hostname_dependent || !request.hostname().is_empty() {
                continue;
            }
            if rule.rule.action == Action::Direct {
                if let Some(decision) = self.direct_fallback(&mut request, index + 1) {
                    return Preflight {
                        decision,
                        definitive: true,
                        match_definitive: false,
                        needs_hostname: false,
                    };
                }
            }
            return Preflight {
                decision: rule.decision(application, "", port),
                definitive: false,
                match_definitive: false,
                needs_hostname: true,
            };
        }
        Preflight {
            decision: Decision::default(),
            definitive: true,
            match_definitive: false,
            needs_hostname: false,
        }
    }

    fn direct_fallback(
        &self,
        request: &mut PreparedRequest<'_>,
        start: usize,
    ) -> Option<Decision<'_>> {
        for rule in self.rules[start..].iter().filter(|r| r.rule.enabled) {
            let Some(application) = rule.match_application(request) else {
                continue;
            };
            let Some(port) = rule.match_port(request.request.target_port) else {
                continue;
            };
            if let Some(host) = rule.match_host(request, &self.computer_name) {
                return (rule.rule.action == Action::Direct)
                    .then(|| rule.decision(application, host, port));
            }
            if rule.hostname_dependent
                && request.hostname().is_empty()
                && rule.rule.action != Action::Direct
            {
                return None;
            }
        }
        Some(Decision::default())
    }
}

fn split_field(input: &str) -> Result<Vec<&str>, &'static str> {
    let mut values = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (index, byte) in input.bytes().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b';' | b',' | b'\n' | b'\r' if !quoted => {
                push_token(&mut values, &input[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if quoted {
        return Err("unclosed quote");
    }
    push_token(&mut values, &input[start..]);
    Ok(values)
}

fn push_token<'a>(tokens: &mut Vec<&'a str>, raw: &'a str) {
    let mut token = raw.trim();
    if token.len() >= 2 && token.starts_with('"') && token.ends_with('"') {
        token = token[1..token.len() - 1].trim();
    }
    if !token.is_empty() {
        tokens.push(token);
    }
}

fn parse_applications(tokens: Vec<&str>) -> Alternatives<Pattern<AppMatcher>> {
    let mut patterns = Vec::with_capacity(tokens.len());
    for token in tokens {
        if token.eq_ignore_ascii_case("any") {
            return Alternatives::Any("Any");
        }
        if token == "*" {
            return Alternatives::Any("*");
        }
        if token.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(pid) = token.parse::<std::num::NonZeroU32>() {
                patterns.push(Pattern {
                    label: token.into(),
                    matcher: AppMatcher::Pid(pid.get()),
                });
                continue;
            }
        }
        let normalized = token.replace('/', "\\");
        let matcher = AppMatcher::Executable {
            full_path: normalized.contains(['\\', ':']),
            glob: normalized.contains(['*', '?']),
        };
        patterns.push(Pattern {
            label: lowercase(&normalized).into_owned(),
            matcher,
        });
    }
    alternatives(patterns)
}

fn parse_hosts(tokens: Vec<&str>) -> Alternatives<Pattern<HostMatcher>> {
    let mut patterns = Vec::with_capacity(tokens.len());
    for token in tokens {
        if token.eq_ignore_ascii_case("any") {
            return Alternatives::Any("Any");
        }
        let (matcher, label) = if token.eq_ignore_ascii_case("%computername%") {
            (HostMatcher::ComputerName, "%computername%".into())
        } else if let Some((ip, bits)) = parse_prefix(token) {
            (HostMatcher::Prefix(ip, bits), token.into())
        } else if let Some((start, end)) = parse_range(token) {
            (HostMatcher::Range(start, end), token.into())
        } else if let Some((ip, zone)) = parse_ip(token) {
            (HostMatcher::Address(ip, zone.into()), token.into())
        } else if let Some((start, end)) = ipv4_glob_range(token) {
            (HostMatcher::Range(start, end), token.into())
        } else {
            let glob = token.contains(['*', '?']);
            let matcher = if glob
                && (token.contains(':')
                    || token
                        .bytes()
                        .all(|b| b.is_ascii_digit() || b".*?".contains(&b)))
            {
                HostMatcher::AddressGlob
            } else if glob {
                HostMatcher::NameGlob
            } else {
                HostMatcher::Name
            };
            (matcher, lowercase(token).into_owned())
        };
        patterns.push(Pattern { label, matcher });
    }
    alternatives(patterns)
}

fn parse_ports(tokens: Vec<&str>) -> Result<Alternatives<Pattern<PortRange>>, String> {
    let mut patterns = Vec::with_capacity(tokens.len());
    let parse = |s: &str| {
        s.trim()
            .parse::<std::num::NonZeroU16>()
            .map(|port| port.get())
            .map_err(|_| format!("invalid port {s:?}"))
    };
    for token in tokens {
        if token.eq_ignore_ascii_case("any") {
            return Ok(Alternatives::Any("Any"));
        }
        let (start, end) = if let Some((a, b)) = token.split_once('-') {
            (parse(a)?, parse(b)?)
        } else {
            let port = parse(token)?;
            (port, port)
        };
        patterns.push(Pattern {
            label: token.into(),
            matcher: start.min(end)..=start.max(end),
        });
    }
    Ok(alternatives(patterns))
}

fn alternatives<T>(patterns: Vec<T>) -> Alternatives<T> {
    if patterns.is_empty() {
        Alternatives::Any("Any")
    } else {
        Alternatives::List(patterns)
    }
}

fn parse_ip(value: &str) -> Option<(IpAddr, &str)> {
    match value.split_once('%') {
        Some((ip, zone)) if !zone.is_empty() => Some((IpAddr::V6(ip.parse().ok()?), zone)),
        Some(_) => None,
        None => Some((value.parse().ok()?, "")),
    }
}

fn parse_prefix(value: &str) -> Option<(IpAddr, u32)> {
    let (ip, bits) = value.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    if !bits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let bits = bits.parse().ok()?;
    (bits <= if ip.is_ipv4() { 32 } else { 128 }).then_some((ip, bits))
}

fn parse_range(value: &str) -> Option<(IpAddr, IpAddr)> {
    let (start, end) = value.split_once('-')?;
    Some((parse_ip(start.trim())?.0, parse_ip(end.trim())?.0))
}

fn ipv4_glob_range(value: &str) -> Option<(IpAddr, IpAddr)> {
    if value.contains([':', '?']) || !value.contains('*') {
        return None;
    }
    let mut lo = [0; 4];
    let mut hi = [0; 4];
    let mut parts = value.split('.');
    for (low, high) in lo.iter_mut().zip(&mut hi) {
        match parts.next()?.trim() {
            "*" => *high = u8::MAX,
            s => {
                let n = s.parse::<i32>().ok()?;
                *low = u8::try_from(n).ok()?;
                *high = *low;
            }
        }
    }
    if parts.next().is_some() {
        return None;
    }
    Some((IpAddr::from(lo), IpAddr::from(hi)))
}

fn ip_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    }
}

fn prefix_contains(network: IpAddr, bits: u32, ip: IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(network), IpAddr::V4(ip)) => {
            bits == 0 || u32::from(network) >> (32 - bits) == u32::from(ip) >> (32 - bits)
        }
        (IpAddr::V6(network), IpAddr::V6(ip)) => {
            bits == 0 || u128::from(network) >> (128 - bits) == u128::from(ip) >> (128 - bits)
        }
        _ => false,
    }
}

fn lowercase(value: &str) -> Cow<'_, str> {
    if value.is_ascii() {
        if value.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(value.to_ascii_lowercase())
        } else {
            Cow::Borrowed(value)
        }
    } else {
        // Go's strings.ToLower uses simple Unicode mapping, one rune at a time.
        Cow::Owned(
            value
                .chars()
                .map(|c| c.to_lowercase().next().unwrap_or(c))
                .collect(),
        )
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v) = (0, 0);
    let mut retry = None;
    while v < value.len() {
        match pattern.get(p) {
            Some(&token) if token == value[v] || token == b'?' => {
                p += 1;
                v += 1;
            }
            Some(b'*') => {
                retry = Some((p + 1, v));
                p += 1;
            }
            _ => match retry {
                Some((next, previous)) => {
                    p = next;
                    v = previous + 1;
                    retry = Some((next, v));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&b| b == b'*')
}
