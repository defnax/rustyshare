//! File list service (0x0019, "file_database"), like libretroshare's p3FileDatabase:
//! friends ask for one folder at a time (`RsFileListsSyncRequestItem`: folder hash, the
//! recursive modification time they know, request id) and get its content
//! (`RsFileListsSyncResponseItem`: FileListIO data, in parts of 20000 bytes), "up to date"
//! or "removed". We ask friends for their root every 2 minutes and for every folder we
//! don't know yet, so their whole list is there to browse and search.

use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use retroshare_compat::{
    basics::SslId,
    services::{service_info::RsServiceInfo, ServiceType},
};
use tokio::{
    select,
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
    time::{interval, Duration},
};

use crate::{
    files::{self, hash_hex, now, Hash, NULL_HASH},
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::{
        intercom::{Intercom, PeerUpdate},
        DataCore,
    },
    services::Service,
};

const SUB_SYNC_REQ: u8 = 0x01;
const SUB_SYNC_RSP: u8 = 0x02;

// RsFileListsItem::FLAGS_*
const FLAGS_SYNC_REQUEST: u32 = 0x0001;
const FLAGS_SYNC_RESPONSE: u32 = 0x0002;
const FLAGS_SYNC_DIR_CONTENT: u32 = 0x0004;
const FLAGS_ENTRY_UP_TO_DATE: u32 = 0x0008;
const FLAGS_ENTRY_WAS_REMOVED: u32 = 0x0010;
const FLAGS_SYNC_PARTIAL: u32 = 0x0020;
const FLAGS_SYNC_PARTIAL_END: u32 = 0x0040;

/// file_sharing_defaults.h
const MAX_DIR_SYNC_RESPONSE_DATA_SIZE: usize = 20000;
const DELAY_BETWEEN_REMOTE_DIRECTORY_SYNC_REQ: u64 = 120;
/// a request without answer is asked again after this
const PENDING_TIMEOUT: u64 = 120;
/// at most this many folder requests waiting per friend
const MAX_PENDING: usize = 10;

pub struct FileLists {
    rx: UnboundedReceiver<Intercom>,
    core: Arc<DataCore>,
    core_tx: UnboundedSender<Intercom>,
    events: UnboundedReceiver<Intercom>,
    /// random bias of the request ids (makeDirSyncReqId())
    bias: u64,
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(at..at + 4)?.try_into().ok()?))
}
fn u64_at(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(d.get(at..at + 8)?.try_into().ok()?))
}
fn hash_at(d: &[u8], at: usize) -> Option<Hash> {
    d.get(at..at + 20)?.try_into().ok()
}

impl FileLists {
    pub async fn new(core: &Arc<DataCore>, core_tx: UnboundedSender<Intercom>, rx: UnboundedReceiver<Intercom>) -> Self {
        let (tx_events, rx_events) = unbounded_channel();
        core.events_subscribe(tx_events).await;
        use nanorand::Rng;
        FileLists { rx, core: core.to_owned(), core_tx, events: rx_events, bias: nanorand::WyRand::new().generate() }
    }

    fn send(&self, peer: Arc<SslId>, sub_type: u8, payload: Vec<u8>) {
        let header = ServiceHeader::new(ServiceType::FileDatabase, sub_type, &payload);
        let _ = self.core_tx.send(Intercom::Send(Packet::new(header.into(), payload, peer)));
    }

    fn request_id(&self, peer: &str, hash: &Hash) -> u64 {
        let mut d = hex::decode(peer).unwrap_or_default();
        d.extend(hash);
        let h = openssl::sha::sha1(&d);
        u64::from_le_bytes(h[..8].try_into().expect("8 bytes")) ^ self.bias
    }

    fn handle_incoming(&mut self, packet: Packet) {
        let header: ServiceHeader = packet.header.to_owned().into();
        let d = &packet.payload;
        let peer = packet.peer_id.to_string();
        match header.sub_type {
            SUB_SYNC_REQ => {
                let (Some(hash), Some(_flags), Some(known_ts), Some(req_id)) =
                    (hash_at(d, 0), u32_at(d, 20), u32_at(d, 24), u64_at(d, 28))
                else {
                    return warn!("[file lists] broken sync request from {peer}");
                };
                self.handle_request(packet.peer_id.clone(), &hash, known_ts, req_id);
            }
            SUB_SYNC_RSP => {
                let parsed = (|| {
                    let hash = hash_at(d, 0)?;
                    let checksum = hash_at(d, 20)?;
                    let flags = u32_at(d, 40)?;
                    let ts = u32_at(d, 44)?;
                    let req_id = u64_at(d, 48)?;
                    // RsTlvBinaryData (type 0)
                    let len = u32_at(d, 58)? as usize;
                    let data = d.get(62..56 + len)?.to_vec();
                    Some((hash, checksum, flags, ts, req_id, data))
                })();
                let Some((hash, checksum, flags, _ts, req_id, data)) = parsed else {
                    return warn!("[file lists] broken sync response from {peer}");
                };
                self.handle_response(&peer, hash, checksum, flags, req_id, data);
            }
            other => trace!("[file lists] ignoring sub type {other:#04x} from {peer}"),
        }
    }

    /// p3FileDatabase::handleDirSyncRequest()
    fn handle_request(&self, peer: Arc<SslId>, hash: &Hash, known_ts: u32, req_id: u64) {
        let (flags, ts, data) = {
            let Some(f) = files::files() else { return };
            match f.local.by_hash.get(hash).copied() {
                // not ours (anymore), or a folder that is not shared with friends
                None => (FLAGS_SYNC_RESPONSE | FLAGS_ENTRY_WAS_REMOVED, 0, vec![]),
                Some(i) if i != 0 && f.local.dirs[i].flags & files::DIR_FLAGS_BROWSABLE == 0 => {
                    (FLAGS_SYNC_RESPONSE | FLAGS_ENTRY_WAS_REMOVED, 0, vec![])
                }
                Some(i) => {
                    let dir = &f.local.dirs[i];
                    if dir.recurs != known_ts {
                        let data = f.local.serialise_dir(i).unwrap_or_default();
                        (FLAGS_SYNC_RESPONSE | FLAGS_SYNC_DIR_CONTENT, dir.recurs, data)
                    } else {
                        (FLAGS_SYNC_RESPONSE | FLAGS_ENTRY_UP_TO_DATE, dir.recurs, vec![])
                    }
                }
            }
        };
        debug!("[file lists] {peer} asked folder {} -> flags {flags:#x}, {} bytes", hash_hex(hash), data.len());
        // p3FileDatabase::splitAndSendItem()
        let checksum = openssl::sha::sha1(&data);
        let parts: Vec<&[u8]> = if data.len() > MAX_DIR_SYNC_RESPONSE_DATA_SIZE {
            data.chunks(MAX_DIR_SYNC_RESPONSE_DATA_SIZE).collect()
        } else {
            vec![&data[..]]
        };
        let n = parts.len();
        for (i, part) in parts.into_iter().enumerate() {
            let mut f = flags;
            if n > 1 {
                f |= FLAGS_SYNC_PARTIAL;
                if i == n - 1 {
                    f |= FLAGS_SYNC_PARTIAL_END;
                }
            }
            let mut p = Vec::with_capacity(62 + part.len());
            p.extend(hash);
            p.extend(checksum);
            p.extend(f.to_be_bytes());
            p.extend(ts.to_be_bytes());
            p.extend(req_id.to_be_bytes());
            p.extend(0u16.to_be_bytes());
            p.extend(((part.len() + 6) as u32).to_be_bytes());
            p.extend(part);
            self.send(peer.clone(), SUB_SYNC_RSP, p);
        }
    }

    /// p3FileDatabase::recvAndRebuildItem() + handleDirSyncResponse()
    fn handle_response(&self, peer: &str, hash: Hash, checksum: Hash, flags: u32, req_id: u64, data: Vec<u8>) {
        let Some(mut f) = files::files() else { return };
        let tree = f.remote_tree(peer);
        let data = if flags & FLAGS_SYNC_PARTIAL != 0 {
            let entry = tree.partial.entry(req_id).or_insert_with(|| (checksum, vec![]));
            if entry.0 != checksum {
                tree.partial.remove(&req_id);
                return warn!("[file lists] parts with different checksums from {peer}");
            }
            entry.1.extend(data);
            if flags & FLAGS_SYNC_PARTIAL_END == 0 {
                return;
            }
            tree.partial.remove(&req_id).map(|e| e.1).unwrap_or_default()
        } else {
            data
        };
        if openssl::sha::sha1(&data) != checksum {
            return warn!("[file lists] checksum error in the answer from {peer}");
        }
        tree.pending.remove(&req_id);
        if !tree.dirs.contains_key(&hash) {
            return debug!("[file lists] answer for an unknown folder from {peer}");
        }
        if flags & FLAGS_ENTRY_WAS_REMOVED != 0 {
            tree.remove_dir(&hash);
        } else if flags & FLAGS_ENTRY_UP_TO_DATE != 0 {
            if let Some(d) = tree.dirs.get_mut(&hash) {
                d.updated = now();
            }
        } else if flags & FLAGS_SYNC_DIR_CONTENT != 0 {
            if !tree.update_dir(&hash, &data) {
                warn!("[file lists] can't read folder {} from {peer}", hash_hex(&hash));
            }
        }
    }

    /// p3FileDatabase::locked_recursSweepRemoteDirectory(): root every 2 minutes, folders
    /// never fetched, folders the user wants to see again
    async fn sweep(&self) {
        let connected: Vec<Arc<SslId>> = self.core.get_connected_peers().lock().await.0.keys().cloned().collect();
        let mut requests = vec![];
        {
            let Some(mut f) = files::files() else { return };
            let t = now();
            // forget the lists of friends that went offline
            let online: Vec<String> = connected.iter().map(|p| p.to_string()).collect();
            f.remote.retain(|p, _| online.contains(p));
            for peer in &connected {
                let peer_hex = peer.to_string();
                let tree = f.remote_tree(&peer_hex);
                tree.pending.retain(|_, (_, at)| *at + PENDING_TIMEOUT > t);
                let pending_dirs: Vec<Hash> = tree.pending.values().map(|(h, _)| *h).collect();
                let mut want = vec![];
                for (hash, d) in &tree.dirs {
                    let stale = d.updated == 0
                        || (*hash == NULL_HASH && t > d.updated + DELAY_BETWEEN_REMOTE_DIRECTORY_SYNC_REQ);
                    if stale && !pending_dirs.contains(hash) {
                        want.push((*hash, d.recurs, *hash == NULL_HASH));
                    }
                }
                // root first
                want.sort_by_key(|w| !w.2);
                for (hash, recurs, _) in want.into_iter().take(MAX_PENDING.saturating_sub(pending_dirs.len())) {
                    let id = self.request_id(&peer_hex, &hash);
                    tree.pending.insert(id, (hash, t));
                    requests.push((peer.clone(), hash, recurs, id));
                }
            }
        }
        for (peer, hash, recurs, id) in requests {
            trace!("[file lists] asking {peer} for folder {}", hash_hex(&hash));
            let mut p = Vec::with_capacity(36);
            p.extend(hash);
            p.extend(FLAGS_SYNC_REQUEST.to_be_bytes());
            p.extend(recurs.to_be_bytes());
            p.extend(id.to_be_bytes());
            self.send(peer, SUB_SYNC_REQ, p);
        }
    }
}

/// The user opens a friend's folder: ask for it again if it is older than a minute.
pub fn refresh_dir(peer: &str, hash: &Hash) {
    if let Some(mut f) = files::files() {
        if let Some(d) = f.remote.get_mut(peer).and_then(|t| t.dirs.get_mut(hash)) {
            if d.updated != 0 && d.updated + 60 < now() {
                d.updated = 0;
            }
        }
    }
}

#[async_trait]
impl Service for FileLists {
    fn get_id(&self) -> ServiceType {
        ServiceType::FileDatabase
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "file_database")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!("[file lists] service started");
            let mut timer = interval(Duration::from_secs(2));
            loop {
                select! {
                    msg = self.rx.recv() => {
                        match msg {
                            Some(Intercom::Receive(packet)) => self.handle_incoming(packet),
                            Some(_) => {}
                            None => break,
                        }
                    }
                    event = self.events.recv() => {
                        if let Some(Intercom::PeerUpdate(PeerUpdate::Seen(_))) = event {
                            self.sweep().await;
                        }
                    }
                    _ = timer.tick() => self.sweep().await,
                }
            }
        })
    }
}
