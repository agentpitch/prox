use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Flow {
    pub pid: u32,
    pub exe_path: Arc<str>,
    pub client: SocketAddr,
    pub original: SocketAddr,
    pub ipv6: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    AppToListener,
    ListenerToApp,
}

struct Entry {
    flow: Flow,
    last_seen: Instant,
    accepted: bool,
}

#[derive(Default)]
pub struct FlowTable {
    state: RwLock<State>,
}

#[derive(Default)]
struct State {
    flows: HashMap<SocketAddr, Entry>,
    deletes: usize,
    peak: usize,
    on_empty: Option<Arc<dyn Fn() + Send + Sync>>,
}

const COMPACT_THRESHOLD: usize = 64;
const COMPACT_RATIO: usize = 4;

impl FlowTable {
    pub fn register(&self, flow: Flow) {
        let mut state = self.state.write().unwrap();
        state.flows.insert(
            normalized(flow.client),
            Entry {
                flow,
                last_seen: Instant::now(),
                accepted: false,
            },
        );
        state.peak = state.peak.max(state.flows.len());
    }

    pub fn len(&self) -> usize {
        self.state.read().unwrap().flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn lookup(&self, client: SocketAddr) -> Option<Flow> {
        let state = self.state.read().unwrap();
        Some(state.flows.get(&normalized(client))?.flow.clone())
    }

    pub fn mark_accepted(&self, client: SocketAddr) -> Option<Flow> {
        let mut state = self.state.write().unwrap();
        let entry = state.flows.get_mut(&normalized(client))?;
        entry.last_seen = Instant::now();
        entry.accepted = true;
        Some(entry.flow.clone())
    }

    pub fn redirect(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        listener_port: u16,
    ) -> Option<(Flow, Direction)> {
        let state = self.state.read().unwrap();
        if source.port() == listener_port {
            if let Some(entry) = state.flows.get(&normalized(destination)) {
                return Some((entry.flow.clone(), Direction::ListenerToApp));
            }
        }
        let entry = state.flows.get(&normalized(source))?;
        (entry.flow.original == destination).then(|| (entry.flow.clone(), Direction::AppToListener))
    }

    pub fn delete(&self, client: SocketAddr) {
        let on_empty = {
            let mut state = self.state.write().unwrap();
            if state.flows.remove(&normalized(client)).is_none() {
                return;
            }
            state.compact(1)
        };
        if let Some(callback) = on_empty {
            callback();
        }
    }

    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        let on_empty = {
            let mut state = self.state.write().unwrap();
            let before = state.flows.len();
            state.flows.retain(|_, entry| {
                entry.accepted || now.duration_since(entry.last_seen) <= max_age
            });
            let removed = before - state.flows.len();
            if removed == 0 {
                return;
            }
            state.compact(removed)
        };
        if let Some(callback) = on_empty {
            callback();
        }
    }

    pub fn set_on_empty(&self, callback: Option<Arc<dyn Fn() + Send + Sync>>) {
        self.state.write().unwrap().on_empty = callback;
    }
}

impl State {
    fn compact(&mut self, removed: usize) -> Option<Arc<dyn Fn() + Send + Sync>> {
        self.deletes += removed;
        let size = self.flows.len();
        if size == 0 {
            if self.peak >= COMPACT_THRESHOLD {
                self.flows = HashMap::new();
            }
            self.deletes = 0;
            self.peak = 0;
            return self.on_empty.clone();
        }
        if self.deletes >= COMPACT_THRESHOLD && size <= self.peak / COMPACT_RATIO {
            self.flows.shrink_to_fit();
            self.deletes = 0;
            self.peak = size;
        }
        None
    }
}

fn normalized(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(_) => address,
        SocketAddr::V6(address) => {
            if let Some(ip) = address.ip().to_ipv4_mapped() {
                return SocketAddrV4::new(ip, address.port()).into();
            }
            SocketAddrV6::new(*address.ip(), address.port(), 0, address.scope_id()).into()
        }
    }
}
