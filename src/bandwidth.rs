//! Total download / upload limits for all friend connections, like RetroShare's
//! "Download limit" / "Upload limit" (rsConfig->SetMaxDataRates, stored in
//! `general.cfg` as `PQIH_FTR`, see `general_cfg.rs`).
//!
//! Every connection takes tokens from a shared bucket before it writes a packet
//! (upload) and after it has read one (download); when the bucket is empty the
//! connection waits, so TCP slows the other side down.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

/// RetroShare's defaults (DEFAULT_DOWNLOAD_KB_RATE / DEFAULT_UPLOAD_KB_RATE)
pub const DEFAULT_RATE_KB: f32 = 10000.0;
/// RetroShare's MIN_MINIMAL_RATE
pub const MIN_RATE_KB: f32 = 5.0;

pub struct Limiter {
    /// kB/s (1 kB = 1024 bytes)
    rate_kb: Mutex<f32>,
    /// tokens (bytes) and time of the last refill
    bucket: Mutex<(f64, Instant)>,
    total: AtomicU64,
    /// bytes, time and rate of the last `current_kb()` sample
    sample: Mutex<(u64, Instant, f32)>,
}

impl Limiter {
    fn new() -> Self {
        Limiter {
            rate_kb: Mutex::new(DEFAULT_RATE_KB),
            bucket: Mutex::new((0.0, Instant::now())),
            total: AtomicU64::new(0),
            sample: Mutex::new((0, Instant::now(), 0.0)),
        }
    }

    pub fn set_rate(&self, kb: f32) {
        *self.rate_kb.lock().expect("lock poisoned") = kb.max(MIN_RATE_KB);
    }

    pub fn rate(&self) -> f32 {
        *self.rate_kb.lock().expect("lock poisoned")
    }

    /// Takes `bytes` from the bucket and returns how long the caller has to wait.
    fn take(&self, bytes: usize) -> Duration {
        self.total.fetch_add(bytes as u64, Ordering::Relaxed);
        let rate = self.rate() as f64 * 1024.0; // bytes per second
        let burst = rate.max(16.0 * 1024.0); // one second, at least 16 kB
        let mut b = self.bucket.lock().expect("lock poisoned");
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(b.1).as_secs_f64();
        b.0 = (b.0 + elapsed * rate).min(burst);
        b.1 = now;
        b.0 -= bytes as f64;
        if b.0 >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-b.0 / rate)
        }
    }

    /// Counts `bytes` that are sent anyway (control packets: heartbeat, status, chat).
    pub fn take_now(&self, bytes: usize) {
        let _ = self.take(bytes);
    }

    /// For queued bulk data: `None` = send `bytes` now (taken from the bucket), or how
    /// long to wait before asking again. A packet may overdraw the bucket a bit, like
    /// RetroShare's pqistreamer, so large packets don't wait forever.
    pub fn try_take(&self, bytes: usize) -> Option<Duration> {
        let rate = self.rate() as f64 * 1024.0;
        let burst = rate.max(16.0 * 1024.0);
        let mut b = self.bucket.lock().expect("lock poisoned");
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(b.1).as_secs_f64();
        b.0 = (b.0 + elapsed * rate).min(burst);
        b.1 = now;
        if b.0 > 0.0 {
            b.0 -= bytes as f64;
            drop(b);
            self.total.fetch_add(bytes as u64, Ordering::Relaxed);
            None
        } else {
            Some(Duration::from_secs_f64((-b.0 / rate).max(0.005)))
        }
    }

    /// Waits until `bytes` may be sent / have been received.
    pub async fn consume(&self, bytes: usize) {
        let wait = self.take(bytes);
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }

    /// Current rate in kB/s (averaged over the time since the last sample, at least 1 s).
    pub fn current_kb(&self) -> f32 {
        let total = self.total.load(Ordering::Relaxed);
        let mut s = self.sample.lock().expect("lock poisoned");
        let elapsed = s.1.elapsed().as_secs_f32();
        if elapsed >= 1.0 {
            s.2 = total.saturating_sub(s.0) as f32 / 1024.0 / elapsed;
            s.0 = total;
            s.1 = Instant::now();
        }
        s.2
    }
}

static DOWN: OnceLock<Limiter> = OnceLock::new();
static UP: OnceLock<Limiter> = OnceLock::new();

pub fn down() -> &'static Limiter {
    DOWN.get_or_init(Limiter::new)
}

pub fn up() -> &'static Limiter {
    UP.get_or_init(Limiter::new)
}
