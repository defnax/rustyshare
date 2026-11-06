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
/// RsNodeGroupItem: version 1, class CONFIG, type PEER_CONFIG, subtype NODE_GROUP (0x07)
const NODE_GROUP_HEADER: [u8; 4] = [0x01, 0x02, 0x02, 0x07];
const TLV_TYPE_STR_NAME: u16 = 0x0051;
const TLV_TYPE_PGPIDSET: u16 = 0x1023;
/// RS_GROUP_FLAG_STANDARD: the five groups every RetroShare has (can't be renamed / removed)
pub const GROUP_FLAG_STANDARD: u32 = 0x0001;
/// RS_GROUP_ID_* and RS_GROUP_DEFAULT_NAME_*
const STANDARD_GROUPS: [(&str, &str); 5] = [
    ("00000000000000000000000000000001", "Friends"),
    ("00000000000000000000000000000002", "Family"),
    ("00000000000000000000000000000003", "Co-Workers"),
    ("00000000000000000000000000000004", "Other Contacts"),
    ("00000000000000000000000000000005", "Favorites"),
];

/// RetroShare's RsGroupInfo: a friend group (friends by PGP id; one friend can be in
/// several groups)
#[derive(Debug, Clone, serde::Serialize)]
pub struct NodeGroup {
    /// RsNodeGroupId, 32 hex characters
    pub id: String,
    pub name: String,
    pub flag: u32,
    #[serde(rename = "peerIds")]
    pub peer_ids: Vec<String>,
}

fn be_u16(d: &[u8], pos: usize) -> Option<u16> {
    d.get(pos..pos + 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}
fn be_u32(d: &[u8], pos: usize) -> Option<u32> {
    d.get(pos..pos + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// RsNodeGroupItem::serial_process(): u32 (unused), id (16 bytes), name (TLV string),
/// u32 flag, PGP id set (TLV with 8 byte ids)
fn parse_group(p: &[u8]) -> Option<NodeGroup> {
    let mut pos = 4;
    let id = hex::encode(p.get(pos..pos + 16)?);
    pos += 16;
    let (tag, len) = (be_u16(p, pos)?, be_u32(p, pos + 2)? as usize);
    if tag != TLV_TYPE_STR_NAME || len < 6 {
        return None;
    }
    let name = String::from_utf8_lossy(p.get(pos + 6..pos + len)?).to_string();
    pos += len;
    let flag = be_u32(p, pos)?;
    pos += 4;
    let (tag, len) = (be_u16(p, pos)?, be_u32(p, pos + 2)? as usize);
    if tag != TLV_TYPE_PGPIDSET || len < 6 || (len - 6) % 8 != 0 {
        return None;
    }
    let peer_ids = p
        .get(pos + 6..pos + len)?
        .chunks(8)
        .map(hex::encode)
        .collect();
    Some(NodeGroup {
        id,
        name,
        flag,
        peer_ids,
    })
}

fn group_item(g: &NodeGroup) -> Vec<u8> {
    let mut p = 0u32.to_be_bytes().to_vec();
    let mut id = hex::decode(&g.id).unwrap_or_default();
    id.resize(16, 0);
    p.extend(id);
    p.extend(TLV_TYPE_STR_NAME.to_be_bytes());
    p.extend(((g.name.len() + 6) as u32).to_be_bytes());
    p.extend(g.name.as_bytes());
    p.extend(g.flag.to_be_bytes());
    let ids: Vec<u8> = g
        .peer_ids
        .iter()
        .filter_map(|i| hex::decode(i).ok())
        .filter(|b| b.len() == 8)
        .flatten()
        .collect();
    p.extend(TLV_TYPE_PGPIDSET.to_be_bytes());
    p.extend(((ids.len() + 6) as u32).to_be_bytes());
    p.extend(ids);

    let mut item = NODE_GROUP_HEADER.to_vec();
    item.extend(((p.len() + HEADER_SIZE) as u32).to_be_bytes());
    item.extend(p);
    item
}

pub struct PeersCfg {
    path: PathBuf,
    net_items: Vec<PeerNetItem>,
    /// friend groups (RsNodeGroupItem)
    groups: Vec<NodeGroup>,
    other_items: Vec<Vec<u8>>,
}

impl PeersCfg {
    /// Empty config for a location without `peers.cfg`.
    pub fn new_empty(location_path: &Path) -> Self {
        PeersCfg {
            path: location_path.join("config/peers.cfg"),
            net_items: vec![],
            groups: vec![],
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
            if item[0..4] == NODE_GROUP_HEADER {
                match parse_group(&item[HEADER_SIZE..]) {
                    Some(group) => {
                        cfg.groups.push(group);
                        continue;
                    }
                    None => warn!("peers.cfg: can't parse a friend group, keeping it raw"),
                }
            }
            cfg.other_items.push(item.to_vec());
        }
        cfg.add_standard_groups();
        cfg
    }

    /// Like p3PeerMgr: the five standard groups always exist.
    fn add_standard_groups(&mut self) {
        for (id, name) in STANDARD_GROUPS {
            if !self.groups.iter().any(|g| g.id == id) {
                self.groups.push(NodeGroup {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    flag: GROUP_FLAG_STANDARD,
                    peer_ids: vec![],
                });
            }
        }
    }

    // --- friend groups (p3PeerMgr::addGroup, editGroup, removeGroup, assignPeersToGroup)

    pub fn groups(&self) -> Vec<NodeGroup> {
        let mut groups = self.groups.clone();
        groups.sort_by(|a, b| a.id.cmp(&b.id)); // like RetroShare's std::map
        groups
    }

    pub fn add_group(&mut self, name: &str) -> Option<NodeGroup> {
        let name = name.trim();
        if name.is_empty() || self.groups.iter().any(|g| g.name.eq_ignore_ascii_case(name)) {
            return None;
        }
        use nanorand::Rng;
        let mut rng = nanorand::WyRand::new();
        let id = loop {
            let id = format!("{:016x}{:016x}", rng.generate::<u64>(), rng.generate::<u64>());
            if !self.groups.iter().any(|g| g.id == id) {
                break id;
            }
        };
        let group = NodeGroup {
            id,
            name: name.to_owned(),
            flag: 0,
            peer_ids: vec![],
        };
        self.groups.push(group.clone());
        Some(group)
    }

    /// Renames a group (not the standard ones).
    pub fn rename_group(&mut self, id: &str, name: &str) -> bool {
        let name = name.trim();
        if name.is_empty()
            || self
                .groups
                .iter()
                .any(|g| g.id != id && g.name.eq_ignore_ascii_case(name))
        {
            return false;
        }
        match self.groups.iter_mut().find(|g| g.id == id) {
            Some(g) if g.flag & GROUP_FLAG_STANDARD == 0 => {
                g.name = name.to_owned();
                true
            }
            _ => false,
        }
    }

    /// Removes a group (not the standard ones).
    pub fn remove_group(&mut self, id: &str) -> bool {
        let before = self.groups.len();
        self.groups
            .retain(|g| g.id != id || g.flag & GROUP_FLAG_STANDARD != 0);
        self.groups.len() != before
    }

    /// Adds / removes a friend (PGP id) to / from a group, or from all groups when
    /// `group` is None and `assign` is false (assignPeersToGroup with a null id).
    pub fn assign_to_group(&mut self, group: Option<&str>, pgp_id: &str, assign: bool) -> bool {
        let pgp_id = pgp_id.to_lowercase();
        if group.is_none() && assign {
            return false;
        }
        let mut changed = false;
        for g in self
            .groups
            .iter_mut()
            .filter(|g| group.map_or(true, |id| g.id == id))
        {
            let has = g.peer_ids.contains(&pgp_id);
            if assign && !has {
                g.peer_ids.push(pgp_id.clone());
                changed = true;
            } else if !assign && has {
                g.peer_ids.retain(|p| p != &pgp_id);
                changed = true;
            }
        }
        changed || group.map_or(false, |id| self.groups.iter().any(|g| g.id == id))
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
        for group in self.groups() {
            out.extend(group_item(&group));
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
