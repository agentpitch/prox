use crate::config::{Config, ProxyProfile};
use crate::flow::{Flow, FlowTable};
use crate::monitor::{display_host, Connection, Monitor};
use crate::platform;
use crate::rules::{Action, Engine, MatchDetails, Request};
use crate::sniff::read_prefix;
use crate::upstream::{negotiate_chain, split_host_port, ProxyHop, ProxyKind};
use serde_json::{json, Value};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub struct Routes {
    pub config: Config,
    pub engine: Engine,
}

impl Routes {
    pub fn compile(config: Config) -> Result<Self, String> {
        let name = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_default();
        let engine = config.compile(&name)?;
        Ok(Self { config, engine })
    }
}

pub type SharedRoutes = Arc<RwLock<Arc<Routes>>>;

#[derive(Default)]
pub struct Stop {
    flag: AtomicBool,
    lock: Mutex<()>,
    wake: Condvar,
}

impl Stop {
    pub fn stopped(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
    pub fn signal(&self) {
        let _lock = self.lock.lock().unwrap();
        self.flag.store(true, Ordering::Release);
        self.wake.notify_all();
    }
    pub fn wait(&self, duration: Duration) -> bool {
        let lock = self.lock.lock().unwrap();
        let _pair = self
            .wake
            .wait_timeout_while(lock, duration, |_| !self.stopped())
            .unwrap();
        self.stopped()
    }
    pub fn wait_forever(&self) {
        let lock = self.lock.lock().unwrap();
        let _lock = self.wake.wait_while(lock, |_| !self.stopped()).unwrap();
    }
}

pub struct Active {
    monitor: Arc<Monitor>,
    stop: Arc<Stop>,
    flows: Arc<FlowTable>,
    relay: Option<Relay>,
    #[cfg(windows)]
    divert: Option<crate::windivert::Capture>,
    observer: Option<JoinHandle<()>>,
}

impl Active {
    pub fn start(routes: SharedRoutes, monitor: Arc<Monitor>) -> io::Result<Self> {
        let stop = Arc::new(Stop::default());
        let flows = Arc::new(FlowTable::default());
        let config = routes.read().unwrap().clone();
        let interception = !config.engine.all_enabled_direct();
        let mut relay = None;
        #[cfg(windows)]
        let mut divert = None;
        if interception {
            relay = Some(
                Relay::bind(
                    &config.config,
                    routes.clone(),
                    flows.clone(),
                    monitor.clone(),
                    stop.clone(),
                )
                .map_err(|e| io::Error::other(format!("start transparent listener: {e}")))?,
            );
            #[cfg(windows)]
            {
                divert = Some(
                    crate::windivert::Capture::start(
                        config.config.transparent.listener_port as u16,
                        routes.clone(),
                        flows.clone(),
                        monitor.clone(),
                        stop.clone(),
                    )
                    .map_err(|e| io::Error::other(format!("start WinDivert engine: {e}")))?,
                );
            }
            #[cfg(not(windows))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WinDivert is only available on Windows",
            ));
        }
        let observer = {
            let (monitor, stop) = (monitor.clone(), stop.clone());
            let flows = flows.clone();
            thread::Builder::new()
                .name("pitchprox-observer".into())
                .spawn(move || observe(routes, monitor, flows, stop))?
        };
        if interception {
            monitor.log(
                "info",
                "runtime started with selective interception fast-path",
                None,
            );
        } else {
            monitor.log(
                "info",
                "runtime started in optimized observer-only mode (all enabled rules are direct)",
                None,
            );
        }
        Ok(Self {
            monitor,
            stop,
            flows,
            relay,
            #[cfg(windows)]
            divert,
            observer: Some(observer),
        })
    }

    pub(crate) fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.stop.signal();
        self.monitor.wake_observer();
        #[cfg(windows)]
        self.divert.take();
        self.relay.take();
        if let Some(observer) = self.observer.take() {
            let _ = observer.join();
        }
    }
}

pub fn request<'a>(flow: &'a Flow, hostname: &'a str) -> Request<'a> {
    Request {
        pid: flow.pid,
        app_path: &flow.exe_path,
        hostname,
        target_ip: Some(flow.original.ip()),
        target_port: flow.original.port(),
        target_ip_zone: "",
    }
}

#[derive(Default)]
pub(crate) struct ExeCache {
    entries: HashMap<u32, (Instant, u64, Arc<str>)>,
}

impl ExeCache {
    pub(crate) fn prune(&mut self) {
        self.entries
            .retain(|_, (time, _, _)| time.elapsed() < Duration::from_secs(120));
    }

    pub(crate) fn path(&mut self, pid: u32) -> Arc<str> {
        let entry = self.entries.get(&pid);
        if let Some((time, _, path)) = entry {
            if time.elapsed() < Duration::from_secs(5) {
                return path.clone();
            }
        }
        let known = entry.map_or(0, |(_, creation, _)| *creation);
        let Ok((creation, path)) = platform::process_info(pid, known) else {
            return "".into();
        };
        let path = path.map_or_else(
            || entry.map_or_else(|| "".into(), |(_, _, p)| p.clone()),
            Arc::<str>::from,
        );
        self.entries
            .insert(pid, (Instant::now(), creation, path.clone()));
        path
    }
}

fn observe(routes: SharedRoutes, monitor: Arc<Monitor>, flows: Arc<FlowTable>, stop: Arc<Stop>) {
    let mut seen = HashMap::<String, Connection>::new();
    let mut exe = ExeCache::default();
    loop {
        if stop.stopped() || !monitor.ui_active() {
            for (_, mut conn) in seen.drain() {
                conn.state = "closed".into();
                monitor.upsert(conn);
            }
            seen.shrink_to_fit();
            exe = ExeCache::default();
            if !monitor.wait_ui(|| stop.stopped()) {
                return;
            }
        }
        exe.prune();
        let routes = routes.read().unwrap().clone();
        let mut next = HashMap::new();
        for row in platform::tcp_owners() {
            if row.pid == 0
                || row.state == 2
                || row.local.port() == 0
                || row.remote.port() == 0
                || row.remote.ip().is_unspecified()
                || flows.lookup(row.local).is_some()
            {
                continue;
            }
            let path = exe.path(row.pid);
            let pre = routes.engine.preflight(Request {
                pid: row.pid,
                app_path: &path,
                target_ip: Some(row.remote.ip()),
                target_port: row.remote.port(),
                ..Request::default()
            });
            if !routes.engine.all_enabled_direct()
                && (!pre.definitive || pre.decision.action() != Action::Direct)
            {
                continue;
            }
            let mut entry = Connection::new(
                row.pid,
                &path,
                row.local,
                row.remote,
                "",
                pre.decision,
                "open",
            );
            if let Some(old) = seen.remove(&entry.id) {
                entry.created_at = old.created_at;
                entry.bytes_up = old.bytes_up;
                entry.bytes_down = old.bytes_down;
            } else {
                let labels = if pre.match_definitive {
                    pre.decision.conditions
                } else {
                    MatchDetails::default()
                };
                monitor.rule_hit(&entry, labels, "direct_observer");
            }
            monitor.upsert(entry.clone());
            next.insert(entry.id.clone(), entry);
        }
        for (_, mut conn) in seen.drain() {
            conn.state = "closed".into();
            monitor.upsert(conn);
        }
        seen = next;
        stop.wait(Duration::from_secs(10));
    }
}

pub fn bind_listener(address: SocketAddr, v6_only: bool) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(v6_only)?;
    }
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    socket.bind(&address.into())?;
    socket.listen(128)?;
    Ok(socket.into())
}

pub fn wake_listener(address: SocketAddr) {
    let ip = match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::from(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::from(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let _ = TcpStream::connect_timeout(
        &SocketAddr::new(ip, address.port()),
        Duration::from_millis(100),
    );
}

struct Relay {
    stop: Arc<Stop>,
    workers: Vec<(SocketAddr, JoinHandle<()>)>,
    shared: Arc<RelayShared>,
}
struct RelayShared {
    routes: SharedRoutes,
    flows: Arc<FlowTable>,
    monitor: Arc<Monitor>,
    stop: Arc<Stop>,
    sockets: Mutex<Vec<TcpStream>>,
    wake: Condvar,
    handlers: Mutex<usize>,
}

impl Relay {
    fn bind(
        cfg: &Config,
        routes: SharedRoutes,
        flows: Arc<FlowTable>,
        monitor: Arc<Monitor>,
        stop: Arc<Stop>,
    ) -> io::Result<Self> {
        let transparent = &cfg.transparent;
        let remote = Arc::new(RelayShared {
            routes,
            flows,
            monitor,
            stop: stop.clone(),
            sockets: Mutex::new(Vec::new()),
            wake: Condvar::new(),
            handlers: Mutex::new(0),
        });
        let mut relay = Self {
            stop,
            workers: Vec::new(),
            shared: remote.clone(),
        };
        let v4 = if transparent.ipv4_listener.is_empty() {
            "0.0.0.0"
        } else {
            &transparent.ipv4_listener
        };
        let v6 = if transparent.ipv6_listener.is_empty() {
            "::"
        } else {
            &transparent.ipv6_listener
        };
        let mut last_error = None;
        for (host, ipv6) in [(v4, false), (v6, true)] {
            let address = (host, transparent.listener_port as u16)
                .to_socket_addrs()
                .and_then(|mut rows| {
                    rows.find(|addr| addr.is_ipv6() == ipv6)
                        .ok_or_else(|| io::Error::other("no address for requested address family"))
                });
            let listener = address.and_then(|addr| bind_listener(addr, true));
            match listener {
                Ok(listener) => {
                    let bound = listener.local_addr()?;
                    let remote = remote.clone();
                    let worker = thread::Builder::new()
                        .name("pitchprox-relay-listener".into())
                        .spawn(move || relay_loop(listener, remote))?;
                    relay.workers.push((bound, worker));
                    relay.shared.monitor.log(
                        "info",
                        format!(
                            "transparent listener {} on {bound}",
                            if ipv6 { "tcp6" } else { "tcp4" }
                        ),
                        None,
                    );
                }
                Err(err) => {
                    last_error = Some(err);
                }
            }
        }
        if relay.workers.is_empty() {
            return Err(
                last_error.unwrap_or_else(|| io::Error::other("no transparent listener started"))
            );
        }
        Ok(relay)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.signal();
        for (addr, _) in &self.workers {
            wake_listener(*addr);
        }
        for (_, task) in self.workers.drain(..) {
            let _ = task.join();
        }
        for socket in self.shared.sockets.lock().unwrap().iter() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        let lock = self.shared.handlers.lock().unwrap();
        let _lock = self
            .shared
            .wake
            .wait_while(lock, |handlers| *handlers != 0)
            .unwrap();
    }
}

fn relay_loop(listener: TcpListener, worker: Arc<RelayShared>) {
    for stream in listener.incoming() {
        if worker.stop.stopped() {
            break;
        }
        let Ok(stream) = stream else { continue };
        let remote = worker.clone();
        *worker.handlers.lock().unwrap() += 1;
        let task = thread::Builder::new()
            .name("pitchprox-relay-flow".into())
            .spawn(move || {
                let _handler = Handler(remote.clone());
                let _ = relay_flow(stream, &remote);
            });
        if task.is_err() {
            let mut handlers = worker.handlers.lock().unwrap();
            *handlers -= 1;
            worker.wake.notify_all();
        }
    }
}

struct Handler(Arc<RelayShared>);
impl Drop for Handler {
    fn drop(&mut self) {
        let mut handlers = self.0.handlers.lock().unwrap();
        *handlers -= 1;
        self.0.wake.notify_all();
    }
}

struct TrackedSocket<'a> {
    local: SocketAddr,
    peer: SocketAddr,
    worker: &'a RelayShared,
}
impl<'a> TrackedSocket<'a> {
    fn new(stream: &TcpStream, worker: &'a RelayShared) -> io::Result<Self> {
        let local = stream.local_addr()?;
        let peer = stream.peer_addr()?;
        let mut sockets = worker.sockets.lock().unwrap();
        if worker.stop.stopped() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        sockets.push(stream.try_clone()?);
        Ok(Self {
            local,
            peer,
            worker,
        })
    }
}
impl Drop for TrackedSocket<'_> {
    fn drop(&mut self) {
        let mut sockets = self.worker.sockets.lock().unwrap();
        if let Some(i) = sockets.iter().position(|socket| {
            socket.local_addr().ok() == Some(self.local)
                && socket.peer_addr().ok() == Some(self.peer)
        }) {
            sockets.swap_remove(i);
        }
        if sockets.capacity() > 128 && sockets.len() * 4 < sockets.capacity() {
            sockets.shrink_to_fit();
        }
    }
}

fn relay_flow(mut client: TcpStream, worker: &RelayShared) -> io::Result<()> {
    let _socket = TrackedSocket::new(&client, worker)?;
    let peer = client.peer_addr()?;
    let Some(flow) = worker.flows.mark_accepted(peer) else {
        worker.monitor.log(
            "warn",
            format!("no flow for redirected connection from {peer}"),
            None,
        );
        return Ok(());
    };
    let _flow = FlowLifetime(&worker.flows, flow.client);
    let routes = worker.routes.read().unwrap().clone();
    let config = &routes.config.transparent;
    let (prefix, sniff) = read_prefix(
        &client,
        config.sniff_bytes as usize,
        Duration::from_millis(config.sniff_timeout_ms as u64),
    )
    .unwrap_or_else(|err| {
        worker.monitor.log(
            "warn",
            format!("sniff failed for {}: {err}", flow.original),
            None,
        );
        (Vec::new(), None)
    });
    let routes = worker.routes.read().unwrap().clone();
    let host = sniff.as_ref().map_or("", |r| r.hostname.as_str());
    let decision = routes.engine.decide(request(&flow, host));
    let mut conn = Connection::new(
        flow.pid,
        &flow.exe_path,
        flow.client,
        flow.original,
        host,
        decision,
        "opening",
    );
    worker.monitor.upsert(conn.clone());
    worker
        .monitor
        .rule_hit(&conn, decision.conditions, "intercepted");
    if decision.action() == Action::Block {
        conn.state = "blocked".into();
        worker.monitor.upsert(conn.clone());
        worker.monitor.log(
            "info",
            format!(
                "blocked pid={} exe={} host={} dst={} rule={}",
                flow.pid,
                flow.exe_path,
                display_host(&conn),
                flow.original,
                conn.rule_name
            ),
            Some(&conn),
        );
        return Ok(());
    }
    let hops = match routes.config.upstream_hops(decision) {
        Ok(hops) => hops,
        Err(err) => {
            conn.state = "error".into();
            worker.monitor.upsert(conn.clone());
            worker.monitor.log(
                "error",
                format!(
                    "build dialer failed action={} proxy={} chain={} err={err}",
                    conn.action, conn.proxy_id, conn.chain_id
                ),
                Some(&conn),
            );
            return Ok(());
        }
    };
    let target = if !hops.is_empty() && !host.is_empty() {
        host_port(host, flow.original.port())
    } else {
        flow.original.to_string()
    };
    let upstream = dial(&hops, &target, Duration::from_secs(15));
    let mut upstream = match upstream {
        Ok(result) => result,
        Err(err) => {
            conn.state = "error".into();
            worker.monitor.upsert(conn.clone());
            worker.monitor.log(
                "error",
                format!(
                    "upstream dial failed host={} dst={} via={target} err={err}",
                    display_host(&conn),
                    flow.original
                ),
                Some(&conn),
            );
            return Ok(());
        }
    };
    let _tracked_upstream = TrackedSocket::new(&upstream.get_ref().stream, worker)?;
    conn.state = "open".into();
    worker.monitor.upsert(conn.clone());
    worker.monitor.log(
        "info",
        format!(
            "opened pid={} exe={} action={} host={} dst={} via={target}",
            flow.pid,
            flow.exe_path,
            conn.action,
            display_host(&conn),
            flow.original
        ),
        Some(&conn),
    );
    let mut up_write = upstream.get_ref().stream.try_clone()?;
    let mut app_read = client.try_clone()?;
    let app_stop = client.try_clone()?;
    let upstream_stop = upstream.get_ref().stream.try_clone()?;
    let close = || {
        let _ = app_stop.shutdown(Shutdown::Both);
        let _ = upstream_stop.shutdown(Shutdown::Both);
    };
    let (up, down) = thread::scope(|scope| {
        let up = scope.spawn(|| {
            let mut read = prefix.as_slice().chain(&mut app_read);
            let result = copy_track(&mut up_write, &mut read, |count| {
                worker.monitor.transferred(&conn, count, 0)
            });
            close();
            result
        });
        let down = copy_track(&mut client, &mut upstream, |count| {
            worker.monitor.transferred(&conn, 0, count)
        });
        close();
        (up.join().unwrap_or(0), down)
    });
    conn.state = "closed".into();
    conn.bytes_up = up;
    conn.bytes_down = down;
    worker.monitor.upsert(conn.clone());
    worker.monitor.log(
        "info",
        format!(
            "closed pid={} exe={} action={} host={} dst={} bytes_up={up} bytes_down={down}",
            flow.pid,
            flow.exe_path,
            conn.action,
            display_host(&conn),
            flow.original
        ),
        Some(&conn),
    );
    Ok(())
}

struct FlowLifetime<'a>(&'a FlowTable, SocketAddr);
impl Drop for FlowLifetime<'_> {
    fn drop(&mut self) {
        self.0.delete(self.1);
    }
}

fn copy_track(dst: &mut impl Write, src: &mut impl Read, mut record: impl FnMut(u64)) -> u64 {
    let mut buf = vec![0_u8; 32 * 1024];
    let mut total = 0;
    let mut pending = 0;
    let mut recorded_at = Instant::now();
    while let Ok(n) = src.read(&mut buf) {
        if n == 0 {
            break;
        }
        let mut offset = 0;
        while offset < n {
            match dst.write(&buf[offset..n]) {
                Ok(w) if w > 0 => {
                    offset += w;
                    pending += w as u64;
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                _ => {
                    record(pending);
                    return total + pending;
                }
            }
        }
        if pending >= 64 * 1024 || recorded_at.elapsed() >= Duration::from_millis(250) {
            record(pending);
            total += pending;
            pending = 0;
            recorded_at = Instant::now();
        }
    }
    record(pending);
    total + pending
}

pub fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn connect(target: &str, timeout: Duration) -> io::Result<TcpStream> {
    let started = Instant::now();
    let mut error = None;
    let mut addresses: Vec<_> = target.to_socket_addrs()?.collect();
    // Match Go's preference for IPv4 where both families resolve on Windows.
    addresses.sort_by_key(SocketAddr::is_ipv6);
    for addr in addresses {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(err) => error = Some(err),
        }
    }
    Err(error.unwrap_or_else(|| io::Error::other("no addresses for target")))
}

struct Deadline {
    stream: TcpStream,
    deadline: Option<Instant>,
}
impl Deadline {
    fn remaining(&self) -> io::Result<Option<Duration>> {
        self.deadline
            .map(|end| {
                end.checked_duration_since(Instant::now())
                    .filter(|time| !time.is_zero())
                    .ok_or_else(|| io::ErrorKind::TimedOut.into())
            })
            .transpose()
    }
}
impl Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.deadline.is_some() {
            self.stream.set_read_timeout(self.remaining()?)?;
        }
        self.stream.read(buf)
    }
}
impl Write for Deadline {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.deadline.is_some() {
            self.stream.set_write_timeout(self.remaining()?)?;
        }
        self.stream.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn dial(hops: &[ProxyHop<'_>], target: &str, budget: Duration) -> io::Result<BufReader<Deadline>> {
    let deadline = Instant::now() + budget;
    let first = hops.first().map_or(target, |hop| hop.address);
    let stream = connect(first, budget.min(Duration::from_secs(10)))?;
    let mut stream = BufReader::new(Deadline {
        stream,
        deadline: Some(deadline),
    });
    negotiate_chain(&mut stream, hops, target)?;
    stream.get_mut().deadline = None;
    stream.get_ref().stream.set_read_timeout(None)?;
    stream.get_ref().stream.set_write_timeout(None)?;
    Ok(stream)
}

pub fn test_proxy(profile: &ProxyProfile, target: &str) -> Result<Value, String> {
    let start = Instant::now();
    let proxy = profile.address.trim();
    if profile.kind.is_empty() {
        return Err("proxy type is required".into());
    }
    if proxy.is_empty() {
        return Err("proxy address is required".into());
    }
    let raw = target
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let raw = if raw.is_empty() {
        "www.google.com:443"
    } else {
        raw
    };
    let raw = if raw.contains(':') {
        raw.to_string()
    } else {
        format!("{raw}:443")
    };
    let (host, port) = split_host_port(&raw)
        .filter(|(host, port)| !host.is_empty() && !port.is_empty())
        .ok_or_else(|| format!("invalid target {target:?}: use host:port"))?;
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let result = |proxy_reachable, tunnel_reachable, message| {
        json!({
            "ok":tunnel_reachable, "proxy_reachable":proxy_reachable, "tunnel_reachable":tunnel_reachable,
            "proxy_type":profile.kind, "proxy_address": proxy, "target":authority,"duration_ms":start.elapsed().as_millis() as u64,
            "message":message
        })
    };
    if let Err(err) = connect(proxy, Duration::from_secs(5)) {
        return Ok(result(
            false,
            false,
            format!("Proxy {proxy} недоступен: {err}"),
        ));
    }
    let kind = match profile.kind.as_str() {
        "http" => ProxyKind::HttpConnect,
        "socks5" => ProxyKind::Socks5,
        _ => return Err(format!("unsupported proxy type {:?}", profile.kind)),
    };
    let hop = ProxyHop {
        kind,
        address: proxy,
        username: &profile.username,
        password: &profile.password,
    };
    match dial(&[hop], &authority, Duration::from_secs(10)) {
        Ok(_) => Ok(result(
            true,
            true,
            format!("Proxy {proxy} работает, туннель до {authority} открыт"),
        )),
        Err(err) => Ok(result(
            true,
            false,
            format!("Proxy {proxy} отвечает, но туннель до {authority} не открыт: {err}"),
        )),
    }
}
