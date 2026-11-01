//! Own online status (Online / Away / Busy, RetroShare's status service 0x0102) and
//! status message (the "custom state string" of RetroShare's chat service), plus what
//! our friends tell us about theirs.
//!
//! Like libretroshare:
//! - p3StatusService sends our status to a friend when it connects and to all friends
//!   when it changes (`RsStatusItem`).
//! - p3ChatService answers `RS_CHAT_FLAG_REQUEST_CUSTOM_STATE` with our string
//!   (`RS_CHAT_FLAG_CUSTOM_STATE`), and when our string changes it tells the friends
//!   (`RS_CHAT_FLAG_CUSTOM_STATE_AVAILABLE`), who then ask for it.
//!
//! The own values are kept in `config/rustyshare_presence.cfg` (encrypted and signed
//! like the other config files).

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use log::{info, warn};
use retroshare_compat::{
    basics::PeerId,
    serde::to_retroshare_wire,
    services::{chat::ChatStatusItem, ServiceType},
};
use serde::{Deserialize, Serialize};

use crate::{
    low_level_parsing::{headers::ServiceHeader, Packet},
    retroshare_compat::{config_store, ssl_key::SslKey},
};

/// RsStatusValue
pub const STATUS_OFFLINE: u32 = 0;
pub const STATUS_AWAY: u32 = 1;
pub const STATUS_BUSY: u32 = 2;
pub const STATUS_ONLINE: u32 = 3;
pub const STATUS_INACTIVE: u32 = 4;

/// RS_CHAT_FLAG_*
pub const CHAT_FLAG_PRIVATE: u32 = 0x0001;
pub const CHAT_FLAG_CUSTOM_STATE: u32 = 0x0010;
pub const CHAT_FLAG_REQUEST_CUSTOM_STATE: u32 = 0x0040;
pub const CHAT_FLAG_CUSTOM_STATE_AVAILABLE: u32 = 0x0080;

/// RS_PKT_SUBTYPE_CHAT_STATUS
pub const CHAT_SUB_TYPE_CHAT_STATUS: u8 = 0x04;
/// RsStatusItem sub type (RS_PKT_SUBTYPE_DEFAULT)
pub const STATUS_SUB_TYPE: u8 = 0x01;

/// RetroShare limits the custom state string in the GUI, keep it reasonable.
pub const MAX_MESSAGE_LEN: usize = 200;

const FILE: &str = "rustyshare_presence.cfg";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnPresence {
    pub status: u32,
    pub message: String,
    /// when the status was set (StatusInfo::time_stamp)
    #[serde(default)]
    pub time_stamp: u64,
}

impl Default for OwnPresence {
    fn default() -> Self {
        OwnPresence {
            status: STATUS_ONLINE,
            message: String::new(),
            time_stamp: 0,
        }
    }
}

/// What a friend's location told us.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PeerPresence {
    /// RsStatusValue, `STATUS_OFFLINE` when it never sent one
    pub status: u32,
    pub message: String,
    /// when the friend sent its status (StatusInfo::time_stamp)
    pub time_stamp: u64,
}

impl PeerPresence {
    /// The status of a connected friend: RetroShare is online until it says otherwise.
    pub fn effective_status(&self) -> u32 {
        match self.status {
            STATUS_OFFLINE => STATUS_ONLINE,
            status => status,
        }
    }
}

pub struct Presence {
    file: PathBuf,
    pub own: OwnPresence,
    /// by SSL id (hex)
    pub peers: HashMap<String, PeerPresence>,
}

impl Presence {
    pub fn load(config_dir: PathBuf, keys: &SslKey) -> Self {
        let file = config_dir.join(FILE);
        let mut own = OwnPresence::default();
        if file.exists() {
            match config_store::load_file(&file, keys) {
                Ok(data) => match serde_json::from_slice(&data) {
                    Ok(loaded) => own = loaded,
                    Err(err) => warn!("can't read {}: {err}", file.display()),
                },
                Err(err) => warn!("can't load {}: {err}", file.display()),
            }
        }
        // like RetroShare: "offline" / "inactive" are not states you start with
        if !matches!(own.status, STATUS_ONLINE | STATUS_AWAY | STATUS_BUSY) {
            own.status = STATUS_ONLINE;
        }
        Presence {
            file,
            own,
            peers: HashMap::new(),
        }
    }

    pub fn save(&self, keys: &SslKey) {
        let data = match serde_json::to_vec(&self.own) {
            Ok(data) => data,
            Err(err) => return warn!("can't serialise presence: {err}"),
        };
        if let Err(err) = config_store::save_file(&self.file, &data, keys) {
            warn!("can't save {}: {err}", self.file.display());
        }
    }

    pub fn set_peer_status(&mut self, peer: &str, status: u32, send_time: u32) {
        let p = self.peers.entry(peer.to_owned()).or_default();
        p.status = status;
        p.time_stamp = send_time as u64;
    }

    pub fn set_peer_message(&mut self, peer: &str, message: String) {
        info!("[presence] status message of {peer}: {message:?}");
        self.peers.entry(peer.to_owned()).or_default().message = message;
    }

    pub fn peer(&self, peer: &str) -> PeerPresence {
        self.peers.get(peer).cloned().unwrap_or_default()
    }
}

pub fn status_name(status: u32) -> &'static str {
    match status {
        STATUS_AWAY => "away",
        STATUS_BUSY => "busy",
        STATUS_ONLINE => "online",
        STATUS_INACTIVE => "inactive",
        _ => "offline",
    }
}

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or_default()
}

fn to_peer(header: ServiceHeader, payload: Vec<u8>, peer: Option<Arc<PeerId>>) -> Packet {
    match peer {
        Some(peer) => Packet::new(header.into(), payload, peer),
        // the core sends packets without location to all connected friends
        None => Packet::new_without_location(header.into(), payload),
    }
}

/// RsStatusItem (send time, status), to one friend or (None) to all.
pub fn status_packet(peer: Option<Arc<PeerId>>, status: u32) -> Packet {
    let mut payload = now().to_be_bytes().to_vec();
    payload.extend(status.to_be_bytes());
    let header = ServiceHeader::new(ServiceType::Status, STATUS_SUB_TYPE, &payload);
    to_peer(header, payload, peer)
}

/// RsChatStatusItem (flags, string), to one friend or (None) to all.
pub fn chat_status_packet(peer: Option<Arc<PeerId>>, flags: u32, text: &str) -> Packet {
    let item = ChatStatusItem {
        flags,
        status_string: text.to_owned().into(),
    };
    let payload = to_retroshare_wire(&item);
    let header = ServiceHeader::new(ServiceType::Chat, CHAT_SUB_TYPE_CHAT_STATUS, &payload);
    to_peer(header, payload, peer)
}
