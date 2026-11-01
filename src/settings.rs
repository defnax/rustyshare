//! rustyshare's own settings (things RetroShare keeps in files rustyshare doesn't
//! write, like `history.cfg`), stored in `config/rustyshare_settings.cfg`
//! (encrypted and signed like the other config files).
//!
//! Values that other parts read often are mirrored in atomics.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
};

use log::warn;
use serde::{Deserialize, Serialize};

use crate::retroshare_compat::{config_store, ssl_key::SslKey};

const FILE: &str = "rustyshare_settings.cfg";

/// Default of `history_max` (messages kept per chat)
pub const DEFAULT_HISTORY_MAX: usize = 200;
/// RetroShare's RS_GXS_DEFAULT_MSG_REQ_PERIOD: 30 days
pub const DEFAULT_FORUM_SYNC_PERIOD: u32 = 86400 * 30;

static HISTORY_MAX: AtomicUsize = AtomicUsize::new(DEFAULT_HISTORY_MAX);
static FORUM_SYNC_PERIOD: AtomicU32 = AtomicU32::new(DEFAULT_FORUM_SYNC_PERIOD);

/// Messages kept per chat in the chat history.
pub fn history_max() -> usize {
    HISTORY_MAX.load(Ordering::Relaxed)
}

/// Sync period of forums without an own setting, seconds (0 = everything).
pub fn forum_sync_period() -> u32 {
    FORUM_SYNC_PERIOD.load(Ordering::Relaxed)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// messages kept per chat (RetroShare: PRIVATE_SAVECOUNT / LOBBY_SAVECOUNT)
    pub history_max: usize,
    /// default sync period for forums, seconds, 0 = all
    pub forum_sync_period: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            history_max: DEFAULT_HISTORY_MAX,
            forum_sync_period: DEFAULT_FORUM_SYNC_PERIOD,
        }
    }
}

impl Settings {
    pub fn load(config_dir: &std::path::Path, keys: &SslKey) -> Self {
        let file = config_dir.join(FILE);
        let mut s = Settings::default();
        if file.exists() {
            match config_store::load_file(&file, keys) {
                Ok(data) => match serde_json::from_slice(&data) {
                    Ok(loaded) => s = loaded,
                    Err(err) => warn!("can't read {}: {err}", file.display()),
                },
                Err(err) => warn!("can't load {}: {err}", file.display()),
            }
        }
        s.apply();
        s
    }

    /// Keeps values in sane ranges and publishes them.
    pub fn apply(&mut self) {
        self.history_max = self.history_max.clamp(10, 10000);
        HISTORY_MAX.store(self.history_max, Ordering::Relaxed);
        FORUM_SYNC_PERIOD.store(self.forum_sync_period, Ordering::Relaxed);
    }

    pub fn save(&self, config_dir: &std::path::Path, keys: &SslKey) {
        let file: PathBuf = config_dir.join(FILE);
        let data = match serde_json::to_vec(self) {
            Ok(d) => d,
            Err(err) => return warn!("can't serialise settings: {err}"),
        };
        if let Err(err) = config_store::save_file(&file, &data, keys) {
            warn!("can't save {}: {err}", file.display());
        }
    }
}
