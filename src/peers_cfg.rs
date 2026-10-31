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
    config::PeerNetItem,
    serde::{from_retroshare_wire_result, to_retroshare_wire},
};

use crate::retroshare_compat::{config_store, ssl_key::SslKey};

const HEADER_SIZE: usize = 8;
/// version 1, class CONFIG (0x02), type PEER_CONFIG (0x02), subtype PEER_NET (0x03)
const PEER_NET_HEADER: [u8; 4] = [0x01, 0x02, 0x02, 0x03];

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
