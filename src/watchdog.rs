//! Watchdog for "rustyshare hangs / uses a lot of CPU": a plain OS thread writes one
//! line per minute to `rustyshare_watchdog.log` (not through the logger, not to the
//! console, so it keeps working when those are stuck):
//!
//! `19:49:00 UTC  runtime ok  packets in 312/min out 280/min  busiest: gxs0211.tick 3.20s/2400x, ...`
//! `19:50:00 UTC  RUNTIME STALLED for 55 s  packets in 0/min out 0/min`
//!
//! - "runtime ok" with many packets: rustyshare is busy with network work
//! - "STALLED": the async runtime doesn't run anymore (a task spins or blocks)
//! - no new lines at all: the whole process is stuck
//! - lines keep coming but rustyshare.log stays quiet: logging is blocked (on Windows
//!   e.g. a console window in "Select" mode blocks every write to it)

use std::{
    io::Write,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const FILE: &str = "rustyshare_watchdog.log";

pub static PACKETS_IN: AtomicU64 = AtomicU64::new(0);
pub static PACKETS_OUT: AtomicU64 = AtomicU64::new(0);
/// last time (unix seconds) the async runtime ran our heartbeat task
static BEAT: AtomicU64 = AtomicU64::new(0);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn clock(t: u64) -> String {
    let s = t % 86400;
    format!("{:02}:{:02}:{:02} UTC", s / 3600, (s / 60) % 60, s % 60)
}

fn write_line(line: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(FILE) {
        let _ = writeln!(f, "{line}");
    }
}

/// Starts the heartbeat task (needs a tokio runtime) and the watchdog thread.
pub fn start() {
    BEAT.store(now(), Ordering::Relaxed);
    tokio::spawn(async {
        loop {
            BEAT.store(now(), Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    write_line(&format!("{}  rustyshare v{} started", clock(now()), env!("CARGO_PKG_VERSION")));
    let _ = std::thread::Builder::new().name("watchdog".into()).spawn(|| {
        let (mut last_in, mut last_out) = (0, 0);
        loop {
            std::thread::sleep(Duration::from_secs(60));
            let t = now();
            let (p_in, p_out) = (PACKETS_IN.load(Ordering::Relaxed), PACKETS_OUT.load(Ordering::Relaxed));
            let age = t.saturating_sub(BEAT.load(Ordering::Relaxed));
            let state = if age > 20 { format!("RUNTIME STALLED for {age} s") } else { "runtime ok".to_string() };
            write_line(&format!(
                "{}  {state}  packets in {}/min out {}/min  busiest: {}",
                clock(t),
                p_in - last_in,
                p_out - last_out,
                top_spent(8)
            ));
            (last_in, last_out) = (p_in, p_out);
        }
    });
}

// --- simple time accounting: where does the CPU time go? ---------------------------

use std::{collections::HashMap, sync::Mutex, time::Instant};

static SPENT: Mutex<Option<HashMap<String, (u64, Duration)>>> = Mutex::new(None);

/// Measures until dropped: `let _t = watchdog::time("gxs0215.tick");`
pub struct Timing(Option<String>, Instant);

impl Drop for Timing {
    fn drop(&mut self) {
        if let Some(name) = self.0.take() {
            let d = self.1.elapsed();
            if let Ok(mut m) = SPENT.lock() {
                let e = m.get_or_insert_with(HashMap::new).entry(name).or_default();
                e.0 += 1;
                e.1 += d;
            }
        }
    }
}

pub fn time(name: impl Into<String>) -> Timing {
    Timing(Some(name.into()), Instant::now())
}

/// The parts that used the most time since the last call (and resets the counters):
/// "gxs0211.tick 12.3s/2400x, chat.packet 0.4s/120x, ..."
fn top_spent(n: usize) -> String {
    let map = SPENT.lock().ok().and_then(|mut m| m.take()).unwrap_or_default();
    let mut list: Vec<_> = map.into_iter().collect();
    list.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
    list.into_iter()
        .take(n)
        .map(|(name, (count, d))| format!("{name} {:.2}s/{count}x", d.as_secs_f64()))
        .collect::<Vec<_>>()
        .join(", ")
}
