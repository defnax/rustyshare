//! Loading and saving `config/peers.cfg`.
//!
//! Items rustyshare does not understand (groups, permissions, bandwidth, settings, ...)
//! are kept as raw bytes and written back unchanged, so saving never drops data that
//! RetroShare stored. Only the `PeerNetItem`s (one per location: our own and friends)
//! are parsed, changed and re-serialised.

use std::path::{Path, PathBuf};

use byteorder::{ByteOrder, NetworkEndian};
use log::{info, warn};
use retroshare_compat::{
    basics::SslId,
    config::{ConfigKeyValueSet, PeerNetItem},
    serde::{from_retroshare_wire_result, to_retroshare_wire},
};

use crate::retroshare_compat::{config_store, ssl_key::SslKey};

const HEADER_SIZE: usize = 8;
/// version 1, class CONFIG (0x02), type PEER_CONFIG (0x02), subtype PEER_NET (0x03)
const PEER_NET_HEADER: [u8; 4] = [0x01, 0x02, 0x02, 0x03];
/// RsConfigKeyValueSet: version 1, class CONFIG, type GENERAL_CONFIG, subtype KEY_VALUE
/// (p3PeerMgr stores USE_EXTR_IP_FINDER and the proxy settings in one)
const KEY_VALUE_HEADER: [u8; 4] = [0x01, 0x02, 0x01, 0x01];

pub struct PeersCfg {
    path: PathBuf,
    net_items: Vec<PeerNetItem>,
    other_items: Vec<Vec<u8>>,
}

impl PeersCfg {
    /// Empty config for a location without `peers.cfg`.
    pub fn new_empty(location_path: &Path) -> Self {
        PeersCfg {
            path: location_path.join("config/peers.cfg"),
            net_items: vec![],
            other_items: vec![],
        }
    }

    /// Splits decrypted `peers.cfg` data into items.
    pub fn from_plaintext(location_path: &Path, data: &[u8]) -> Self {
        let mut cfg = Self::new_empty(location_path);

        let mut pos = 0;
        while pos + HEADER_SIZE <= data.len() {
            let size = NetworkEndian::read_u32(&data[pos + 4..pos + 8]) as usize;
            if size < HEADER_SIZE || pos + size > data.len() {
                warn!("peers.cfg: broken item at offset {pos}, keeping the rest as is");
                cfg.other_items.push(data[pos..].to_vec());
                break;
            }
            let item = &data[pos..pos + size];
            pos += size;

            if item[0..4] == PEER_NET_HEADER {
                let mut payload = item[HEADER_SIZE..].to_vec();
                match from_retroshare_wire_result::<PeerNetItem>(&mut payload) {
                    Ok(net) => {
                        cfg.net_items.push(net);
                        continue;
                    }
                    Err(err) => warn!("peers.cfg: can't parse a PeerNetItem ({err:?}), keeping it raw"),
                }
            }
            cfg.other_items.push(item.to_vec());
        }
        cfg
    }

    pub fn to_plaintext(&self) -> Vec<u8> {
        let mut out = vec![];
        // location items first, like libretroshare's p3PeerMgr::saveList()
        for item in &self.net_items {
            let payload = to_retroshare_wire(item);
            let mut header = [0u8; HEADER_SIZE];
            header[0..4].copy_from_slice(&PEER_NET_HEADER);
            NetworkEndian::write_u32(&mut header[4..8], (payload.len() + HEADER_SIZE) as u32);
            out.extend_from_slice(&header);
            out.extend(payload);
        }
        for item in &self.other_items {
            out.extend_from_slice(item);
        }
        out
    }

    /// The location's `config` folder.
    pub fn config_dir(&self) -> PathBuf {
        self.path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_default()
    }

    pub fn get(&self, ssl_id: &SslId) -> Option<&PeerNetItem> {
        self.net_items.iter().find(|i| &i.node_peer_id == ssl_id)
    }

    /// Adds a location or replaces the existing entry with the same id.
    pub fn add_or_update(&mut self, item: PeerNetItem) {
        match self
            .net_items
            .iter_mut()
            .find(|i| i.node_peer_id == item.node_peer_id)
        {
            Some(existing) => *existing = item,
            None => self.net_items.push(item),
        }
    }

    /// A value of p3PeerMgr's key/value item (e.g. `USE_EXTR_IP_FINDER`).
    pub fn get_setting(&self, key: &str) -> Option<String> {
        self.other_items
            .iter()
            .filter(|i| i.len() > HEADER_SIZE && i[0..4] == KEY_VALUE_HEADER)
            .find_map(|i| {
                let mut payload = i[HEADER_SIZE..].to_vec();
                let set = from_retroshare_wire_result::<ConfigKeyValueSet>(&mut payload).ok()?;
                set.0
                    .into_iter()
                    .find(|(k, _)| AsRef::<str>::as_ref(k) == key)
                    .map(|(_, v)| v.into())
            })
    }

    /// Sets a value in p3PeerMgr's key/value item (created if there is none).
    pub fn set_setting(&mut self, key: &str, value: &str) {
        let pos = self
            .other_items
            .iter()
            .position(|i| i.len() > HEADER_SIZE && i[0..4] == KEY_VALUE_HEADER);
        let mut set = match pos {
            Some(p) => {
                let mut payload = self.other_items[p][HEADER_SIZE..].to_vec();
                match from_retroshare_wire_result::<ConfigKeyValueSet>(&mut payload) {
                    Ok(set) => set,
                    Err(err) => {
                        return warn!("peers.cfg: can't parse the settings item ({err:?}), not changing it")
                    }
                }
            }
            None => ConfigKeyValueSet::default(),
        };
        set.0.retain(|k, _| AsRef::<str>::as_ref(k) != key);
        set.0.insert(key.into(), value.into());

        let payload = to_retroshare_wire(&set);
        let mut item = vec![0u8; HEADER_SIZE];
        item[0..4].copy_from_slice(&KEY_VALUE_HEADER);
        NetworkEndian::write_u32(&mut item[4..8], (payload.len() + HEADER_SIZE) as u32);
        item.extend(payload);
        match pos {
            Some(p) => self.other_items[p] = item,
            None => self.other_items.push(item),
        }
    }

    pub fn remove(&mut self, ssl_id: &SslId) -> bool {
        let before = self.net_items.len();
        self.net_items.retain(|i| &i.node_peer_id != ssl_id);
        before != self.net_items.len()
    }

    /// Encrypts, signs and writes `peers.cfg` (with `.tmp` backup).
    pub fn save(&self, keys: &SslKey) -> std::io::Result<()> {
        config_store::save_file(&self.path, &self.to_plaintext(), keys)?;
        info!("saved {}", self.path.display());
        Ok(())
    }
}
