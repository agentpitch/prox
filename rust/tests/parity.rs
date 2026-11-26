use pitchprox_core::config::{Config, ProxyChain, ProxyProfile, Store};
use pitchprox_core::flow::{Direction, Flow, FlowTable};
use pitchprox_core::packet::Packet;
use pitchprox_core::rules::{Action, Engine, MatchDetails, Request, Rule};
use pitchprox_core::sniff::{inspect, read_prefix, Protocol, SniffResult};
use pitchprox_core::upstream::{negotiate_chain, ProxyHop, ProxyKind};
use pitchprox_core::webui::static_asset;
use std::fs;
use std::io::{self, BufReader, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn rule(id: &str, applications: &str, hosts: &str, ports: &str, action: Action) -> Rule {
    Rule {
        id: id.into(),
        name: id.into(),
        enabled: true,
        applications: applications.into(),
        target_hosts: hosts.into(),
        target_ports: ports.into(),
        action,
        ..Rule::default()
    }
}

#[test]
fn first_matching_rule_and_authored_alternatives() {
    let engine = Engine::compile(
        vec![
            rule(
                "ordered",
                r#""C:/Apps, Enterprise/BROWSER.*"; browser.exe; 007"#,
                "other.example; *.Example.NET; 192.168.1.*",
                "444 - 440; 443",
                Action::Chain,
            ),
            rule("default", "*", "Any", "Any", Action::Direct),
        ],
        "workstation",
    )
    .unwrap();
    let request = Request {
        pid: 7,
        app_path: r"C:\Apps, Enterprise\Browser.exe",
        hostname: "Media.Example.NET",
        target_ip: Some("192.168.1.5".parse().unwrap()),
        target_port: 443,
        ..Request::default()
    };
    let decision = engine.decide(request);
    assert_eq!(decision.rule.unwrap().id, "ordered");
    assert_eq!(decision.action(), Action::Chain);
    assert_eq!(
        decision.conditions,
        MatchDetails {
            application: r"c:\apps, enterprise\browser.*",
            host: "*.example.net",
            port: "444 - 440",
        }
    );
    let pid_match = engine.decide(Request {
        app_path: "other.exe",
        ..request
    });
    assert_eq!(pid_match.conditions.application, "007");
    let ip_match = engine.preflight(Request {
        hostname: "",
        ..request
    });
    assert!(ip_match.match_definitive);
    assert_eq!(ip_match.decision.conditions.host, "192.168.1.*");
}

#[test]
fn host_star_is_ip_glob_and_any_is_unconditional() {
    let engine = Engine::compile(
        vec![
            rule("ip-only", "Any; *", "*", "Any", Action::Block),
            rule("default", "*; Any", "Any", "Any", Action::Direct),
        ],
        "",
    )
    .unwrap();
    let named = Request {
        hostname: "localhost",
        ..Request::default()
    };
    assert_eq!(engine.decide(named).rule.unwrap().id, "default");
    assert_eq!(engine.decide(named).conditions.application, "*");
    let addressed = Request {
        target_ip: Some("::1".parse().unwrap()),
        ..named
    };
    assert_eq!(engine.decide(addressed).rule.unwrap().id, "ip-only");
    assert_eq!(engine.decide(addressed).conditions.application, "Any");
}

#[test]
fn preflight_skips_sniff_only_if_every_reachable_outcome_is_direct() {
    let direct_by_name = rule("local", "*", "%ComputerName%", "443", Action::Direct);
    let fallback = rule("default", "*", "Any", "Any", Action::Direct);
    let request = Request {
        target_port: 443,
        ..Request::default()
    };
    let engine = Engine::compile(
        vec![direct_by_name.clone(), fallback.clone()],
        "WORKSTATION",
    )
    .unwrap();
    assert!(engine.all_enabled_direct());
    let bypass = engine.preflight(request);
    assert!(bypass.definitive);
    assert!(!bypass.match_definitive);
    assert_eq!(bypass.decision.rule.unwrap().id, "default");

    let ipv6_proxy = rule("proxy", "*", "2001:db8::/32", "443", Action::Proxy);
    let engine =
        Engine::compile(vec![direct_by_name, ipv6_proxy, fallback], "WORKSTATION").unwrap();
    let request = Request {
        target_ip: Some("2001:db8::19".parse().unwrap()),
        ..request
    };
    assert!(!engine.all_enabled_direct());
    let sniff = engine.preflight(request);
    assert!(sniff.needs_hostname);
    assert!(!sniff.definitive);
    assert_eq!(sniff.decision.rule.unwrap().id, "local");
    assert_eq!(
        engine
            .decide(Request {
                hostname: "workstation",
                ..request
            })
            .rule
            .unwrap()
            .id,
        "local"
    );
    assert_eq!(
        engine
            .decide(Request {
                hostname: "other",
                ..request
            })
            .action(),
        Action::Proxy
    );
}

#[test]
fn parse_rejects_typographical_errors_in_disabled_rules() {
    let mut invalid = rule("bad", "*", "\"unclosed", "Any", Action::Direct);
    invalid.enabled = false;
    assert_eq!(
        Engine::compile(vec![invalid.clone()], "").unwrap_err(),
        "rule \"bad\" target hosts: unclosed quote"
    );
    invalid.target_hosts = "Any".into();
    invalid.target_ports = "0; Any".into();
    assert_eq!(
        Engine::compile(vec![invalid], "").unwrap_err(),
        "rule \"bad\" target ports: invalid port \"0\""
    );
}

#[test]
fn ipv4_options_and_ipv6_extension_chain_preserve_tcp_offset() {
    let mut ipv4 = [0; 44];
    ipv4[0] = 0x46;
    ipv4[9] = 6;
    ipv4[24..28].copy_from_slice(&[0xc0, 0x00, 0x01, 0xbb]);
    ipv4[37] = 0x12;
    let mut packet = Packet::parse(&mut ipv4).unwrap();
    assert_eq!(packet.src_port, 49152);
    assert_eq!(packet.dst_port, 443);
    assert!(packet.syn && packet.ack);
    packet
        .set_destination("127.0.0.1".parse().unwrap(), 26001)
        .unwrap();
    assert_eq!(&packet.bytes()[16..20], &[127, 0, 0, 1]);
    assert_eq!(&packet.bytes()[26..28], &26001_u16.to_be_bytes());

    let mut ipv6 = [0; 76];
    ipv6[0] = 0x60;
    ipv6[6] = 0;
    ipv6[40] = 44;
    ipv6[48] = 6;
    ipv6[56..60].copy_from_slice(&[0xc0, 0x00, 0x01, 0xbb]);
    ipv6[69] = 0x05;
    let mut packet = Packet::parse(&mut ipv6).unwrap();
    assert!(packet.ipv6 && packet.rst && packet.fin);
    packet.set_source("::1".parse().unwrap(), 127).unwrap();
    assert_eq!(packet.bytes()[23], 1);
    assert_eq!(&packet.bytes()[56..58], &127_u16.to_be_bytes());
    ipv6[51] = 8;
    assert_eq!(
        Packet::parse(&mut ipv6).unwrap_err(),
        "non-initial ipv6 fragment"
    );
}

fn vector(bytes: &[u8]) -> Vec<u8> {
    let mut vector = (bytes.len() as u16).to_be_bytes().to_vec();
    vector.extend_from_slice(bytes);
    vector
}

fn client_hello(name: &[u8], chunks: &[usize]) -> Vec<u8> {
    let names = vector(&[&[0], vector(name).as_slice()].concat());
    let extensions = vector(&[&[0, 0], vector(&names).as_slice()].concat());
    let mut body = vec![0; 34];
    body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    body.extend(extensions);
    let len = (body.len() as u32).to_be_bytes();
    let handshake = [&[1], &len[1..], body.as_slice()].concat();
    let mut stream = Vec::new();
    let mut begin = 0;
    for end in chunks.iter().copied().chain([handshake.len()]) {
        stream.extend_from_slice(&[0x16, 3, 3]);
        stream.extend(vector(&handshake[begin..end]));
        begin = end;
    }
    stream
}

#[test]
fn sniff_http_and_tls_without_accepting_unsafe_names() {
    let host = inspect(b"GET / HTTP/1.1\r\nhOsT: Test.Example.:443\r\n\r\n").unwrap();
    assert_eq!(
        host,
        SniffResult {
            hostname: "test.example".into(),
            protocol: Protocol::Http
        }
    );
    let tunnel = inspect(b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!(tunnel.hostname, "2001:db8::1");

    for chunks in [&[][..], &[2, 21][..]] {
        let input = client_hello(b"Test.Example.", chunks);
        assert_eq!(
            inspect(&input),
            Some(SniffResult {
                hostname: "test.example".into(),
                protocol: Protocol::Tls
            })
        );
        for length in 0..input.len() {
            assert_eq!(inspect(&input[..length]), None);
        }
    }
    assert_eq!(inspect(&client_hello(b"foo\r\n.example", &[])), None);
}

#[test]
fn sniff_returns_a_fragmented_socket_prefix_and_restores_the_read_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let request = b"PATCH / HTTP/1.1\r\nHost: fragmented.test\r\n\r\nhello";
    let send = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(&request[..3]).unwrap();
        std::thread::sleep(Duration::from_millis(15));
        stream.write_all(&request[3..]).unwrap();
    });
    let (stream, _) = listener.accept().unwrap();
    let original_timeout = Some(Duration::from_secs(3));
    stream.set_read_timeout(original_timeout).unwrap();
    let (mut data, sniff) = read_prefix(&stream, 4096, Duration::from_secs(1)).unwrap();
    assert_eq!(sniff.unwrap().hostname, "fragmented.test");
    assert_eq!(stream.read_timeout().unwrap(), original_timeout);
    (&stream).read_to_end(&mut data).unwrap();
    assert_eq!(data, request);
    send.join().unwrap();
}

#[test]
fn flow_mapping_handles_both_directions_and_expires_unaccepted_entries() {
    let table = FlowTable::default();
    let became_empty = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&became_empty);
    table.set_on_empty(Some(Arc::new(move || {
        calls.fetch_add(1, Ordering::Relaxed);
    })));
    let client = "192.0.2.5:51234".parse().unwrap();
    let original = "198.51.100.5:443".parse().unwrap();
    let listener = "127.0.0.1:26001".parse().unwrap();
    table.register(Flow {
        pid: 7,
        exe_path: "test.exe".into(),
        client,
        original,
        ipv6: false,
    });
    let mapped_client = "[::ffff:192.0.2.5]:51234".parse().unwrap();
    assert_eq!(table.lookup(mapped_client).unwrap().pid, 7);
    assert_eq!(
        table.redirect(client, original, 26001).unwrap().1,
        Direction::AppToListener
    );
    assert_eq!(
        table.redirect(listener, client, 26001).unwrap().1,
        Direction::ListenerToApp
    );
    assert!(table.redirect(client, listener, 26001).is_none());
    table.mark_accepted(mapped_client).unwrap();
    table.register(Flow {
        pid: 11,
        exe_path: "other.exe".into(),
        client: "192.0.2.5:51235".parse().unwrap(),
        original,
        ipv6: false,
    });
    std::thread::sleep(Duration::from_millis(1));
    table.cleanup(Duration::ZERO);
    assert_eq!(table.len(), 1);
    table.delete(mapped_client);
    table.delete(mapped_client);
    assert!(table.is_empty());
    assert_eq!(became_empty.load(Ordering::Relaxed), 1);
}

struct Transcript {
    replies: Cursor<Vec<u8>>,
    requests: Vec<u8>,
}

impl Read for Transcript {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        self.replies.read(data)
    }
}

impl Write for Transcript {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.requests.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn mixed_proxy_chain_keeps_data_buffered_beyond_connect_response() {
    let mut replies = b"HTTP/1.1 200 Connection Established\r\nVia: test\r\n\r\n".to_vec();
    replies.extend([5, 2, 1, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0, 80]);
    replies.extend(b"application payload");
    let mut stream = BufReader::new(Transcript {
        replies: Cursor::new(replies),
        requests: Vec::new(),
    });
    let proxies = [
        ProxyHop {
            kind: ProxyKind::HttpConnect,
            address: "first.example:8080",
            username: "user",
            password: "secret",
        },
        ProxyHop {
            kind: ProxyKind::Socks5,
            address: "second.example:1080",
            username: "a",
            password: "b",
        },
    ];
    negotiate_chain(&mut stream, &proxies, "example.com:443").unwrap();
    let mut payload = String::new();
    stream.read_to_string(&mut payload).unwrap();
    assert_eq!(payload, "application payload");
    let sent = stream.into_inner().requests;
    let first = b"CONNECT second.example:1080 HTTP/1.1\r\nHost: second.example:1080\r\nProxy-Connection: Keep-Alive\r\nProxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n";
    assert!(sent.starts_with(first));
    let mut rest = vec![5, 2, 0, 2, 1, 1, b'a', 1, b'b', 5, 1, 0, 3, 11];
    rest.extend(b"example.com");
    rest.extend(443_u16.to_be_bytes());
    assert_eq!(&sent[first.len()..], rest);
}

#[test]
fn connect_response_limit_applies_before_header_allocation_grows() {
    let mut replies = b"HTTP/1.1 200 Connection Established\r\nX: ".to_vec();
    replies.extend(std::iter::repeat_n(b'a', 64 << 10));
    replies.extend(b"\r\n\r\n");
    let mut stream = BufReader::new(Transcript {
        replies: Cursor::new(replies),
        requests: Vec::new(),
    });
    let proxy = ProxyHop {
        kind: ProxyKind::HttpConnect,
        address: "first.example:8080",
        username: "",
        password: "",
    };
    let failure = negotiate_chain(&mut stream, &[proxy], "example.com:443").unwrap_err();
    assert_eq!(
        failure.to_string(),
        "http CONNECT response headers exceed 65536 bytes"
    );
}

#[test]
fn embedded_assets_are_the_original_webui_bytes() {
    assert_eq!(
        static_asset("/").unwrap().bytes,
        include_bytes!("../../internal/webui/dist/index.html")
    );
    assert_eq!(
        static_asset("/a/../app.js").unwrap().bytes,
        include_bytes!("../../internal/webui/dist/app.js")
    );
    assert_eq!(
        static_asset("/monitor").unwrap().bytes,
        static_asset("/").unwrap().bytes
    );
    assert!(static_asset("/absent.js").is_none());
}

#[test]
fn portable_config_reads_bom_and_null_lists_and_persists_a_new_revision() {
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("pitchprox-rust-{}-{start}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let path = directory.join("pitchProx.config.json");
    let mut content = vec![0xef, 0xbb, 0xbf];
    content.extend_from_slice(
        br#"{
        "version": 1,
        "http": {"listen": " localhost:18080 "},
        "transparent": {"listener_port": 26001, "sniff_bytes": 4096, "sniff_timeout_ms": 1500},
        "proxies": null,
        "chains": null,
        "rules": [{
            "id": "one",
            "name": "One",
            "enabled": true,
            "applications": "*",
            "target_hosts": "Any",
            "target_ports": "Any",
            "action": " DIRECT ",
            "chain_id": "unused"
        }]
    }"#,
    );
    fs::write(&path, content).unwrap();
    let mut store = Store::load_or_create(path.clone()).unwrap();
    let initial = store.current().clone();
    assert_eq!(initial.http.listen, "localhost:18080");
    assert_eq!(initial.retention_minutes, 7);
    assert_eq!(initial.dropped_log_max_bytes, 10 * 1024 * 1024);
    assert!(initial.proxies.is_none());
    assert!(initial.chains.is_empty());
    let rule = &initial.rules.as_ref().unwrap()[0];
    assert_eq!(rule.action, "direct");
    assert_eq!(rule.chain_id, "");
    assert!(initial.compile("WORKSTATION").unwrap().all_enabled_direct());

    let mut next = initial.clone();
    next.retention_minutes = 13;
    let saved = store.save(next).unwrap();
    assert!(saved.updated_at > initial.updated_at);
    let reloaded = Store::load_or_create(path.clone()).unwrap();
    assert_eq!(reloaded.current(), saved);
    fs::remove_file(path).unwrap();
    fs::remove_dir(directory).unwrap();
}

#[test]
fn config_rejects_enabled_rules_with_disabled_proxy_and_preserves_password_whitespace() {
    let mut config = Config::fresh();
    config.proxies = Some(vec![ProxyProfile {
        id: " p1 ".into(),
        address: "localhost:8080".into(),
        kind: " HTTP CONNECT ".into(),
        password: " keep spaces ".into(),
        ..ProxyProfile::default()
    }]);
    let mut config = config.canonicalize().unwrap();
    let proxy = &config.proxies.as_ref().unwrap()[0];
    assert_eq!(proxy.kind, "http");
    assert_eq!(proxy.password, " keep spaces ");
    let rule = &mut config.rules.as_mut().unwrap()[1];
    rule.action = "proxy".into();
    rule.proxy_id = "p1".into();
    assert_eq!(
        config.canonicalize().unwrap_err(),
        "enabled rule \"Default\" references unknown or disabled proxy \"p1\""
    );
}

#[test]
fn selected_chain_uses_configured_order_and_keeps_proxy_credentials() {
    let mut config = Config::fresh();
    config.proxies = Some(vec![
        ProxyProfile {
            id: "exit".into(),
            kind: "socks5".into(),
            address: "exit.test:1080".into(),
            enabled: true,
            ..ProxyProfile::default()
        },
        ProxyProfile {
            id: "entry".into(),
            kind: "http".into(),
            address: "entry.test:8080".into(),
            username: "user".into(),
            password: "secret".into(),
            enabled: true,
            ..ProxyProfile::default()
        },
    ]);
    config.chains.push(ProxyChain {
        id: "ordered".into(),
        proxy_ids: Some(vec!["entry".into(), "exit".into()]),
        enabled: true,
        ..ProxyChain::default()
    });
    let default = &mut config.rules.as_mut().unwrap()[1];
    default.action = "chain".into();
    default.chain_id = "ordered".into();
    let config = config.canonicalize().unwrap();
    let engine = config.compile("WORKSTATION").unwrap();
    let selected = engine.decide(Request::default());
    let hops = config.upstream_hops(selected).unwrap();
    assert_eq!(hops.len(), 2);
    assert_eq!(hops[0].kind, ProxyKind::HttpConnect);
    assert_eq!(hops[0].address, "entry.test:8080");
    assert_eq!(hops[0].username, "user");
    assert_eq!(hops[0].password, "secret");
    assert_eq!(hops[1].kind, ProxyKind::Socks5);
    assert_eq!(hops[1].address, "exit.test:1080");
}
