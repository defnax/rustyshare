//! Reputation of identities, following libretroshare's p3GxsReputation
//! (retroshare/rsreputations.h): our own opinion about identities, the opinions our
//! friends sent us, and the overall reputation level computed from both.
//!
//! Saved encrypted and signed in `config/rustyshare_reputation.cfg` (rustyshare's own
//! format, RetroShare's reputation config is left untouched).

use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use log::{info, warn};
use serde::{Deserialize, Serialize};

use crate::retroshare_compat::{config_store, ssl_key::SslKey};

pub const REPUTATION_FILE: &str = "rustyshare_reputation.cfg";
const SAVE_INTERVAL: Duration = Duration::from_secs(60); // RS: at most once a minute

/// `RsOpinion`
pub const OPINION_NEGATIVE: u8 = 0;
pub const OPINION_NEUTRAL: u8 = 1;
pub const OPINION_POSITIVE: u8 = 2;

/// `RsReputationLevel`
pub const LEVEL_LOCALLY_NEGATIVE: u8 = 0;
pub const LEVEL_REMOTELY_NEGATIVE: u8 = 1;
pub const LEVEL_NEUTRAL: u8 = 2;
pub const LEVEL_REMOTELY_POSITIVE: u8 = 3;
pub const LEVEL_LOCALLY_POSITIVE: u8 = 4;

/// RS: REPUTATION_DEFAULT_MIN_VOTES_FOR_REMOTELY_POSITIVE / _NEGATIVE
const MIN_VOTES_REMOTELY_POSITIVE: u32 = 1;
const MIN_VOTES_REMOTELY_NEGATIVE: u32 = 1;

/// like `safe_convert_uint32t_to_opinion()`: unknown values count as neutral
pub fn opinion_from_u32(v: u32) -> u8 {
    if v > OPINION_POSITIVE as u32 {
        OPINION_NEUTRAL
    } else {
        v as u8
    }
}

fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OwnOpinion {
    op: u8,
    ts: u32,
}

#[derive(Default, Serialize, Deserialize)]
struct Stored {
    /// gxs id (hex) -> own opinion
    own: HashMap<String, OwnOpinion>,
    /// gxs id (hex) -> friend location (hex) -> opinion (never neutral)
    friends: HashMap<String, HashMap<String, u8>>,
    /// friend location (hex) -> time of the newest update we got from it
    peer_latest: HashMap<String, u32>,
}

/// `RsReputationInfo`, names as in RetroShare's JSON API
#[derive(Debug, Clone, Serialize)]
pub struct ReputationInfo {
    #[serde(rename = "mOwnOpinion")]
    pub own_opinion: u8,
    #[serde(rename = "mFriendsPositiveVotes")]
    pub friends_positive: u32,
    #[serde(rename = "mFriendsNegativeVotes")]
    pub friends_negative: u32,
    #[serde(rename = "mFriendAverageScore")]
    pub friend_average: f32,
    #[serde(rename = "mOverallReputationLevel")]
    pub overall_level: u8,
}

pub struct Reputations {
    file: PathBuf,
    data: Stored,
    dirty: bool,
    last_save: Instant,
}

impl Reputations {
    pub fn load(config_dir: PathBuf, keys: &SslKey) -> Self {
        let file = config_dir.join(REPUTATION_FILE);
        let mut data = Stored::default();
        if file.exists() {
            match config_store::load_file(&file, keys) {
                Ok(bytes) => match serde_json::from_slice(&bytes) {
                    Ok(d) => data = d,
                    Err(err) => warn!("can't read {}: {err}", file.display()),
                },
                Err(err) => warn!("can't load {}: {err}", file.display()),
            }
            info!(
                "loaded reputations ({} own opinions, {} identities rated by friends)",
                data.own.len(),
                data.friends.len()
            );
        }
        Reputations {
            file,
            data,
            dirty: false,
            last_save: Instant::now(),
        }
    }

    /// `setOwnOpinion()`. Neutral is kept with its time stamp, so friends learn that
    /// we withdrew an opinion.
    pub fn set_own(&mut self, id: &str, op: u8) {
        self.data.own.insert(
            id.to_lowercase(),
            OwnOpinion {
                op: op.min(OPINION_POSITIVE),
                ts: now(),
            },
        );
        self.dirty = true;
    }

    pub fn own(&self, id: &str) -> u8 {
        self.data
            .own
            .get(&id.to_lowercase())
            .map(|o| o.op)
            .unwrap_or(OPINION_NEUTRAL)
    }

    /// Own opinions changed after `since`, oldest first (for `SendReputations()`).
    pub fn own_updates_since(&self, since: u32) -> Vec<(String, u8, u32)> {
        let mut list: Vec<_> = self
            .data
            .own
            .iter()
            .filter(|(_, o)| o.ts > since && o.ts != 0)
            .map(|(id, o)| (id.to_owned(), o.op, o.ts))
            .collect();
        list.sort_by_key(|(_, _, ts)| *ts);
        list
    }

    /// `locked_updateOpinion()`: a friend's opinion about an identity.
    pub fn set_friend_opinion(&mut self, peer: &str, id: &str, op: u8) {
        let id = id.to_lowercase();
        let peer = peer.to_lowercase();
        if op == OPINION_NEUTRAL {
            if let Some(map) = self.data.friends.get_mut(&id) {
                if map.remove(&peer).is_some() {
                    self.dirty = true;
                }
                if map.is_empty() {
                    self.data.friends.remove(&id);
                }
            }
        } else if self.data.friends.entry(id).or_default().insert(peer, op) != Some(op) {
            self.dirty = true;
        }
    }

    pub fn peer_latest(&self, peer: &str) -> u32 {
        self.data
            .peer_latest
            .get(&peer.to_lowercase())
            .copied()
            .unwrap_or(0)
    }

    pub fn set_peer_latest(&mut self, peer: &str, ts: u32) {
        self.data.peer_latest.insert(peer.to_lowercase(), ts);
        self.dirty = true;
    }

    /// `getReputationInfo()` (without RetroShare's banned-node list).
    /// `pgp_linked`: the identity is signed by a profile, `pgp_known`: by a profile we
    /// know (changes how much friends' votes weigh in the average, like RetroShare).
    pub fn info(&self, id: &str, pgp_linked: bool, pgp_known: bool) -> ReputationInfo {
        let id = id.to_lowercase();
        let own = self.own(&id);
        let (mut pos, mut neg, mut total) = (0u32, 0u32, 0i32);
        if let Some(map) = self.data.friends.get(&id) {
            for op in map.values() {
                match *op {
                    OPINION_POSITIVE => pos += 1,
                    OPINION_NEGATIVE => neg += 1,
                    _ => {}
                }
                total += *op as i32 - 1;
            }
        }

        // Reputation::updateReputation()
        let friend_average = if pos + neg == 0 {
            1.0
        } else {
            let bias = if pgp_known {
                10.0
            } else if pgp_linked {
                5.0
            } else {
                2.0
            };
            if total > 0 {
                2.0 - (-(total as f32) / bias).exp()
            } else {
                (total as f32 / bias).exp()
            }
        };

        let overall_level = if own == OPINION_NEGATIVE {
            LEVEL_LOCALLY_NEGATIVE
        } else if own == OPINION_POSITIVE {
            LEVEL_LOCALLY_POSITIVE
        } else if pos >= neg + MIN_VOTES_REMOTELY_POSITIVE {
            LEVEL_REMOTELY_POSITIVE
        } else if pos + MIN_VOTES_REMOTELY_NEGATIVE <= neg {
            LEVEL_REMOTELY_NEGATIVE
        } else {
            LEVEL_NEUTRAL
        };

        ReputationInfo {
            own_opinion: own,
            friends_positive: pos,
            friends_negative: neg,
            friend_average,
            overall_level,
        }
    }

    /// `isIdentityBanned()`: our own opinion is negative.
    pub fn is_banned(&self, id: &str) -> bool {
        self.own(id) == OPINION_NEGATIVE
    }

    /// Saves if something changed and the last save is long enough ago (or `force`).
    pub fn save(&mut self, keys: &SslKey, force: bool) {
        if !self.dirty || (!force && self.last_save.elapsed() < SAVE_INTERVAL) {
            return;
        }
        self.last_save = Instant::now();
        let bytes = match serde_json::to_vec(&self.data) {
            Ok(b) => b,
            Err(err) => return warn!("can't serialise reputations: {err}"),
        };
        match config_store::save_file(&self.file, &bytes, keys) {
            Ok(()) => self.dirty = false,
            Err(err) => warn!("can't save {}: {err}", self.file.display()),
        }
    }
}
