//! Loading and saving `config/general.cfg`, RetroShare's p3GeneralConfig: a list of
//! `RsConfigKeyValueSet` items (key / value strings). rustyshare only changes the keys
//! it knows (the bandwidth limits, `PQIH_FTR`); all other keys and items are written
//! back unchanged.

use std::{collections::BTreeMap, path::PathBuf};

use byteorder::{ByteOrder, NetworkEndian};
use log::{info, warn};
use retroshare_compat::{
    config::ConfigKeyValueSet,
    serde::{from_retroshare_wire_result, to_retroshare_wire},
};

use crate::retroshare_compat::{config_store, ssl_key::SslKey};

const HEADER_SIZE: usize = 8;
/// version 1, class CONFIG (0x02), type GENERAL_CONFIG (0x01), subtype KEY_VALUE (0x01)
const KEY_VALUE_HEADER: [u8; 4] = [0x01, 0x02, 0x01, 0x01];
/// p3GeneralConfig::saveList() starts a new item above this size
const MAX_ITEM_TLV_SIZE: usize = 4000;

/// p3ServerConfig: "max download, max upload, max download when idle, max upload when idle"
pub const KEY_RATES: &str = "PQIH_FTR";

pub struct GeneralCfg {
    path: PathBuf,
    settings: BTreeMap<String, String>,
    other_items: Vec<Vec<u8>>,
    /// false if the file could not be read: then it is never overwritten
    writable: bool,
}

impl GeneralCfg {
    pub fn load(config_dir: PathBuf, keys: &SslKey) -> Self {
        let path = config_dir.join("general.cfg");
        let mut cfg = GeneralCfg {
            path,
            settings: BTreeMap::new(),
            other_items: vec![],
            writable: true,
        };
        if !cfg.path.exists() {
            return cfg; // RetroShare creates it on its first save, so do we
        }
        let data = match config_store::load_file(&cfg.path, keys) {
            Ok(data) => data,
            Err(err) => {
                warn!("can't load {}: {err}", cfg.path.display());
                cfg.writable = false;
                return cfg;
            }
        };

        let mut pos = 0;
        while pos + HEADER_SIZE <= data.len() {
            let size = NetworkEndian::read_u32(&data[pos + 4..pos + 8]) as usize;
            if size < HEADER_SIZE || pos + size > data.len() {
                warn!("general.cfg: broken item at offset {pos}, keeping the rest as is");
                cfg.other_items.push(data[pos..].to_vec());
                break;
            }
            let item = &data[pos..pos + size];
            pos += size;

            if item[0..4] == KEY_VALUE_HEADER {
                let mut payload = item[HEADER_SIZE..].to_vec();
                match from_retroshare_wire_result::<ConfigKeyValueSet>(&mut payload) {
                    Ok(set) => {
                        for (k, v) in set.0 {
                            cfg.settings.insert(k.into(), v.into());
                        }
                        continue;
                    }
                    Err(err) => {
                        warn!("general.cfg: can't parse a key/value item ({err:?}), not changing the file");
                        cfg.writable = false;
                    }
                }
            }
            cfg.other_items.push(item.to_vec());
        }
        cfg
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.settings.get(key)
    }

    pub fn set(&mut self, key: &str, value: String) {
        self.settings.insert(key.to_owned(), value);
    }

    fn to_plaintext(&self) -> Vec<u8> {
        let mut out = vec![];
        let push = |set: &ConfigKeyValueSet, out: &mut Vec<u8>| {
            let payload = to_retroshare_wire(set);
            let mut header = [0u8; HEADER_SIZE];
            header[0..4].copy_from_slice(&KEY_VALUE_HEADER);
            NetworkEndian::write_u32(&mut header[4..8], (payload.len() + HEADER_SIZE) as u32);
            out.extend_from_slice(&header);
            out.extend(payload);
        };

        let mut set = ConfigKeyValueSet::default();
        let mut size = 0;
        for (k, v) in &self.settings {
            set.0.insert(k.to_owned().into(), v.to_owned().into());
            size += k.len() + v.len() + 18; // TLV headers of the pair
            if size > MAX_ITEM_TLV_SIZE {
                push(&set, &mut out);
                set = ConfigKeyValueSet::default();
                size = 0;
            }
        }
        if !set.0.is_empty() {
            push(&set, &mut out);
        }
        for item in &self.other_items {
            out.extend_from_slice(item);
        }
        out
    }

    /// Encrypts, signs and writes `general.cfg` (with `.tmp` backup).
    pub fn save(&self, keys: &SslKey) -> std::io::Result<()> {
        if !self.writable {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "general.cfg could not be read, not overwriting it",
            ));
        }
        config_store::save_file(&self.path, &self.to_plaintext(), keys)?;
        info!("saved {}", self.path.display());
        Ok(())
    }

    /// Download / upload limit in kB/s (`PQIH_FTR`, "%f %f %f %f" or "%f %f").
    pub fn rates(&self) -> Option<(f32, f32)> {
        let text = self.get(KEY_RATES)?;
        let v: Vec<f32> = text
            .split_whitespace()
            .filter_map(|x| x.parse().ok())
            .collect();
        (v.len() >= 2).then(|| (v[0], v[1]))
    }

    /// Writes the limits like p3ServerConfig::setMaxDataRates() (the "when idle"
    /// values are kept, or set to the same rates).
    pub fn set_rates(&mut self, down: f32, up: f32) {
        let old: Vec<f32> = self
            .get(KEY_RATES)
            .map(|t| t.split_whitespace().filter_map(|x| x.parse().ok()).collect())
            .unwrap_or_default();
        let (down_idle, up_idle) = if old.len() == 4 {
            (old[2], old[3])
        } else {
            (down, up)
        };
        self.set(
            KEY_RATES,
            format!("{down:.6} {up:.6} {down_idle:.6} {up_idle:.6}"),
        );
    }
}
