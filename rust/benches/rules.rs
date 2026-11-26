use pitchprox_core::rules::{Action, Engine, Request, Rule};
use std::hint::black_box;
#[cfg(not(feature = "bench-allocations"))]
use std::time::{Duration, Instant};

#[cfg(feature = "bench-allocations")]
mod allocations {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

    struct CountingAllocator;
    static BYTES: AtomicUsize = AtomicUsize::new(0);
    static CALLS: AtomicUsize = AtomicUsize::new(0);

    // The wrapper delegates ownership and alignment to System unchanged.
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            BYTES.fetch_add(layout.size(), Relaxed);
            CALLS.fetch_add(1, Relaxed);
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { System.dealloc(pointer, layout) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    pub fn measure(run: impl FnOnce()) -> (usize, usize) {
        let bytes = BYTES.load(Relaxed);
        let calls = CALLS.load(Relaxed);
        run();
        (BYTES.load(Relaxed) - bytes, CALLS.load(Relaxed) - calls)
    }
}

fn engine() -> Engine {
    let mut rules = vec![
        Rule {
            id: "local-direct".into(),
            name: "Local direct".into(),
            enabled: true,
            applications: "*".into(),
            target_hosts: "192.168.1.*".into(),
            target_ports: "443".into(),
            ..Rule::default()
        },
        Rule {
            id: "github-direct".into(),
            name: "GitHub direct".into(),
            enabled: true,
            applications: "*".into(),
            target_hosts: "github.com".into(),
            target_ports: "443".into(),
            ..Rule::default()
        },
    ];
    rules.extend((0..256).map(|i| Rule {
        id: format!("filler-{i}"),
        name: format!("Filler {i}"),
        enabled: true,
        applications: "helper.exe".into(),
        target_hosts: "203.0.113.0/24".into(),
        target_ports: "8000-9000".into(),
        ..Rule::default()
    }));
    rules.push(Rule {
        id: "default".into(),
        name: "Default proxy".into(),
        enabled: true,
        applications: "*".into(),
        target_hosts: "Any".into(),
        target_ports: "Any".into(),
        action: Action::Proxy,
        proxy_id: "p1".into(),
        ..Rule::default()
    });
    Engine::compile(rules, "WORKSTATION").unwrap()
}

fn main() {
    let engine = engine();
    for (name, ip, hostname_needed) in [
        ("DefinitiveDirect", "192.168.1.44", false),
        ("HostnameNeeded", "140.82.121.4", true),
    ] {
        let request = Request {
            pid: 100,
            app_path: r"C:\Apps\browser.exe",
            target_ip: Some(ip.parse().unwrap()),
            target_port: 443,
            ..Request::default()
        };
        let decision = engine.preflight(request);
        assert_eq!(decision.definitive, !hostname_needed);
        assert_eq!(decision.needs_hostname, hostname_needed);

        measure(name, || {
            black_box(engine.preflight(black_box(request)));
        });
    }
}

#[cfg(not(feature = "bench-allocations"))]
fn measure(name: &str, run: impl Fn()) {
    let mut iterations = 0;
    let started = Instant::now();
    let elapsed = loop {
        for _ in 0..4096 {
            run();
        }
        iterations += 4096;
        let elapsed = started.elapsed();
        if elapsed >= Duration::from_secs(1) {
            break elapsed;
        }
    };
    let ns_per_op = elapsed.as_secs_f64() * 1e9 / f64::from(iterations);
    println!("PreflightLargeRuleSet{name} {iterations} {ns_per_op:.2} ns/op");
}

#[cfg(feature = "bench-allocations")]
fn measure(name: &str, run: impl Fn()) {
    const ITERATIONS: usize = 4096;
    let (bytes, calls) = allocations::measure(|| {
        for _ in 0..ITERATIONS {
            run();
        }
    });
    println!(
        "PreflightLargeRuleSet{name} {:.2} requested B/op {:.2} allocs/op",
        bytes as f64 / ITERATIONS as f64,
        calls as f64 / ITERATIONS as f64
    );
}
