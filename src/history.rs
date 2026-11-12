//! Chat history (private chats and chat rooms), kept in memory for the web UI and
//! saved encrypted and signed in `config/rustyshare_history.cfg`, the same way
//! RetroShare's config files are stored (see `config_store`).
//!
//! RetroShare keeps its history in `history.cfg` (p3HistoryMgr); this is rustyshare's
//! own simpler format (JSON inside the encrypted envelope), RetroShare's file is left
//! untouched.

use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    time::{Duration, Instant},
};

use log::{info, warn};
use serde::{Deserialize, Serialize};

use crate::retroshare_compat::{config_store, ssl_key::SslKey};

pub const HISTORY_FILE: &str = "rustyshare_history.cfg";
/// messages kept per chat (RetroShare's default for rooms is in the same range)
pub const MAX_MESSAGES_PER_CHAT: usize = 200;
/// don't encrypt + sign the file for every single message
const SAVE_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// nickname (rooms) or friend name (private chats), empty for own messages
    pub from: String,
    /// author's GXS id in rooms, empty otherwise
    #[serde(default)]
    pub author: String,
    /// message as received (RetroShare sends HTML)
    pub text: String,
    /// send time, unix seconds
    pub time: u32,
    /// false for messages we sent
    pub incoming: bool,
}

/// Which chat a message belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HistoryChat {
    Room(u64),
    Private(String),
    /// distant chat (GXS tunnel id, hex)
    Distant(String),
}

impl HistoryChat {
    fn key(&self) -> String {
        match self {
            HistoryChat::Room(id) => format!("room:{id}"),
            HistoryChat::Private(id) => format!("peer:{id}"),
            HistoryChat::Distant(id) => format!("distant:{id}"),
        }
    }
}

/// One chat as returned to the web UI. The room id is a string, JavaScript numbers
/// can't hold 64 bit ids.
#[derive(Debug, Serialize)]
pub struct HistoryChatOut {
    pub room_id: String,
    pub peer_id: String,
    /// distant chat id (empty for rooms and friends)
    pub distant_id: String,
    pub messages: Vec<HistoryEntry>,
}

pub struct ChatHistory {
    file: PathBuf,
    chats: HashMap<String, VecDeque<HistoryEntry>>,
    dirty: bool,
    last_save: Instant,
}

impl ChatHistory {
    /// Loads the history of a location (empty if there is none yet).
    pub fn load(config_dir: PathBuf, keys: &SslKey) -> Self {
        let file = config_dir.join(HISTORY_FILE);
        let mut chats = HashMap::new();
        if file.exists() {
            match config_store::load_file(&file, keys) {
                Ok(data) => match serde_json::from_slice(&data) {
                    Ok(loaded) => {
                        chats = loaded;
                        info!("loaded chat history ({} chats)", chats.len());
                    }
                    Err(err) => warn!("can't read {}: {err}", file.display()),
                },
                Err(err) => warn!("can't load {}: {err}", file.display()),
            }
        }
        ChatHistory {
            file,
            chats,
            dirty: false,
            last_save: Instant::now(),
        }
    }

    pub fn add(&mut self, chat: &HistoryChat, entry: HistoryEntry, keys: &SslKey) {
        let list = self.chats.entry(chat.key()).or_default();
        list.push_back(entry);
        while list.len() > crate::settings::history_max() {
            list.pop_front();
        }
        self.dirty = true;
        if self.last_save.elapsed() >= SAVE_INTERVAL {
            self.save(keys);
        }
    }

    /// Applies a new size limit (Settings page).
    pub fn trim(&mut self, max: usize) {
        for list in self.chats.values_mut() {
            while list.len() > max {
                list.pop_front();
                self.dirty = true;
            }
        }
    }

    /// Deletes the whole history (Settings page).
    pub fn clear(&mut self) {
        self.chats.clear();
        self.dirty = true;
    }

    /// Writes the file if something changed (called regularly and after messages).
    pub fn save(&mut self, keys: &SslKey) {
        if !self.dirty {
            return;
        }
        self.last_save = Instant::now();
        let data = match serde_json::to_vec(&self.chats) {
            Ok(data) => data,
            Err(err) => return warn!("can't serialise chat history: {err}"),
        };
        match config_store::save_file(&self.file, &data, keys) {
            Ok(()) => self.dirty = false,
            Err(err) => warn!("can't save {}: {err}", self.file.display()),
        }
    }

    pub fn get_all(&self) -> Vec<HistoryChatOut> {
        self.chats
            .iter()
            .filter_map(|(key, list)| {
                let (room_id, peer_id, distant_id) = match key.split_once(':') {
                    Some(("room", id)) => (id.to_owned(), String::new(), String::new()),
                    Some(("peer", id)) => (String::new(), id.to_owned(), String::new()),
                    Some(("distant", id)) => (String::new(), String::new(), id.to_owned()),
                    _ => return None,
                };
                Some(HistoryChatOut {
                    room_id,
                    peer_id,
                    distant_id,
                    messages: list.iter().cloned().collect(),
                })
            })
            .collect()
    }
}
