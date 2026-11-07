//! Contacts among the GXS identities (People page), like RetroShare's
//! p3IdService::setAsRegularContact() / isARegularContact():
//! identities marked as contact, plus the identities signed by friends' profiles
//! (RetroShare's AUTO_SET_FRIEND_IDENTITIES_AS_CONTACT, on by default) unless they were
//! removed from the contacts by hand.
//!
//! Kept in `config/rustyshare_contacts.cfg` (encrypted and signed like the other
//! config files). RetroShare keeps its list in the identity service's own config.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use log::warn;
use serde::{Deserialize, Serialize};

use crate::retroshare_compat::{config_store, ssl_key::SslKey};

const FILE: &str = "rustyshare_contacts.cfg";

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    /// marked as contact (identity ids, lower case hex)
    contacts: HashSet<String>,
    /// friends' identities removed from the contacts by hand
    removed: HashSet<String>,
}

pub struct Contacts {
    file: PathBuf,
    saved: Saved,
    /// PGP link of identities: bytes 8..28 of the identity data, SHA1(id || PGP
    /// fingerprint); empty for anonymous identities. Read once per identity.
    pub links: HashMap<String, Vec<u8>>,
}

impl Contacts {
    pub fn load(config_dir: PathBuf, keys: &SslKey) -> Self {
        let file = config_dir.join(FILE);
        let mut saved = Saved::default();
        if file.exists() {
            match config_store::load_file(&file, keys) {
                Ok(data) => match serde_json::from_slice(&data) {
                    Ok(s) => saved = s,
                    Err(err) => warn!("can't read {}: {err}", file.display()),
                },
                Err(err) => warn!("can't load {}: {err}", file.display()),
            }
        }
        Contacts {
            file,
            saved,
            links: HashMap::new(),
        }
    }

    fn save(&self, keys: &SslKey) {
        match serde_json::to_vec(&self.saved) {
            Ok(data) => {
                if let Err(err) = config_store::save_file(&self.file, &data, keys) {
                    warn!("can't save {}: {err}", self.file.display());
                }
            }
            Err(err) => warn!("can't serialise contacts: {err}"),
        }
    }

    pub fn set(&mut self, id: &str, contact: bool, keys: &SslKey) {
        let id = id.to_lowercase();
        if contact {
            self.saved.contacts.insert(id.clone());
            self.saved.removed.remove(&id);
        } else {
            self.saved.contacts.remove(&id);
            self.saved.removed.insert(id);
        }
        self.save(keys);
    }

    /// Is `id` a contact? `friend_fingerprints` are the friends' PGP fingerprints.
    pub fn is_contact(&self, id: &str, friend_fingerprints: &[Vec<u8>]) -> bool {
        let id = id.to_lowercase();
        if self.saved.contacts.contains(&id) {
            return true;
        }
        if self.saved.removed.contains(&id) {
            return false;
        }
        match self.links.get(&id) {
            Some(link) if link.len() == 20 => friend_fingerprints.iter().any(|fpr| {
                let mut input = id.clone().into_bytes();
                input.extend(fpr);
                openssl::sha::sha1(&input)[..] == link[..]
            }),
            _ => false,
        }
    }
}
