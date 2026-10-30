use std::io::Read;
use std::{fs::File, path::Path};

use openpgp::{
    cert::CertParser,
    parse::{PacketParser, Parse},
    Cert,
};
use sequoia_openpgp as openpgp;

use crate::basics::*;

// Old RetroShare (OpenPGP-SDK) uses "pgp", newer RetroShare (RNP) uses "rnp".
const KEYRING_BASE_DIRS: [&'static str; 2] = ["pgp", "rnp"];
const KEYRING_PUBKEY: &'static str = "retroshare_public_keyring.gpg";
const KEYRING_PRIVKEY: &'static str = "retroshare_secret_keyring.gpg";

fn read_key_ring(file: &str) -> Result<Vec<Cert>, std::io::Error> {
    let mut f = File::open(file)?;
    let mut keyring = Vec::new();
    f.read_to_end(&mut keyring)?;
    let ppr = PacketParser::from_bytes(&keyring).expect("failed to parse keyring");
    let mut ring = Vec::new();
    for certo in CertParser::from(ppr) {
        match certo {
            Ok(cert) => ring.push(cert),
            Err(why) => println!("Error reading keyring: {}", why),
        }
    }
    Ok(ring)
}

pub struct Keyring {
    public_keys: Vec<Cert>,
    priv_keys: Vec<Cert>,
}

impl Keyring {
    pub fn new() -> Keyring {
        Keyring {
            public_keys: Vec::new(),
            priv_keys: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn public_keys(&self) -> &Vec<Cert> {
        &self.public_keys
    }

    #[allow(dead_code)]
    pub fn priv_keys(&self) -> &Vec<Cert> {
        &self.priv_keys
    }
}

impl Keyring {
    pub fn parse(&mut self, path: &Path) {
        let dir = match KEYRING_BASE_DIRS
            .iter()
            .map(|d| path.join(d))
            .find(|d| d.join(KEYRING_PUBKEY).exists() || d.join(KEYRING_PRIVKEY).exists())
        {
            Some(dir) => dir,
            None => {
                println!(
                    "no keyring found in {}\\pgp or {}\\rnp (no profile yet)",
                    path.display(),
                    path.display()
                );
                self.public_keys.clear();
                self.priv_keys.clear();
                return;
            }
        };
        println!("using keyring folder {}", dir.display());

        self.priv_keys = read_key_ring(dir.join(KEYRING_PRIVKEY).to_str().unwrap())
            .unwrap_or_else(|err| {
                println!("failed to read secret keyring: {err}");
                Vec::new()
            });
        // newer (RNP based) RetroShare may not write a public keyring file
        self.public_keys = read_key_ring(dir.join(KEYRING_PUBKEY).to_str().unwrap())
            .unwrap_or_else(|_| {
                println!("no public keyring file, using public part of the secret keyring");
                Vec::new()
            });
        // make sure our own public keys are always in the public ring
        for cert in &self.priv_keys {
            if !self.public_keys.iter().any(|c| c.fingerprint() == cert.fingerprint()) {
                self.public_keys.push(cert.clone().strip_secret_key_material());
            }
        }

        println!(
            "loaded keyrings: public keys: {} private keys: {}",
            self.public_keys.len(),
            self.priv_keys.len()
        );
    }

    pub fn get_key_by_id_str(&self, id_in_hex: &str, priv_key: bool) -> Option<&Cert> {
        let ring = if priv_key {
            &self.priv_keys
        } else {
            &self.public_keys
        };

        ring.iter().find(|&x| x.keyid().to_hex() == id_in_hex)
    }

    pub fn get_key_by_id_bytes(&self, id_in_bytes: &PgpId, priv_key: bool) -> Option<&Cert> {
        let ring = if priv_key {
            &self.priv_keys
        } else {
            &self.public_keys
        };

        ring.iter().find(|&x| x.keyid().as_bytes() == id_in_bytes.0)
    }

    #[allow(dead_code)]
    pub fn get_priv_keys(&self) -> &Vec<Cert> {
        &self.priv_keys
    }
}
