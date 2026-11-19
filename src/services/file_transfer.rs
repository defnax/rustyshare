//! File transfer service (0x0017, "ft"), like libretroshare's ftServer / ftDataMultiplex
//! for transfers between friends:
//!
//! - serving: `RsFileTransferDataRequestItem` (offset, size, file) is answered with
//!   `RsFileTransferDataItem`s of at most 240 kB; chunk map requests with a full map,
//!   chunk CRC requests with the SHA1 of that 1 MB chunk
//! - downloading: the file is asked from the sources that are online in slices of
//!   256 kB, a few at a time, written to the partial file; a finished file is checked
//!   (SHA1 of the whole file = its hash) and moved to the download folder

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

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
    time::interval,
};

use crate::{
    files::{self, add_range, chunk_len, hash_hex, now, Hash, Upload, CHUNK_SIZE},
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::{intercom::Intercom, DataCore},
    services::Service,
};

const SUB_DATA_REQUEST: u8 = 0x01;
const SUB_DATA: u8 = 0x02;
const SUB_CHUNK_MAP_REQUEST: u8 = 0x04;
const SUB_CHUNK_MAP: u8 = 0x05;
const SUB_CHUNK_CRC_REQUEST: u8 = 0x08;
const SUB_CHUNK_CRC: u8 = 0x09;

const TLV_TYPE_FILEITEM: u16 = 0x1000;
const TLV_TYPE_FILEDATA: u16 = 0x1002;
const TLV_TYPE_UINT64_OFFSET: u16 = 0x0041;
const TLV_TYPE_BIN_FILEDATA: u16 = 0x0140;

/// ftServer::sendData(): MAX_FT_CHUNK
const MAX_FT_CHUNK: usize = 240 * 1024;
/// what we ask at once
const SLICE: u64 = 256 * 1024;
/// requests on their way per download
const MAX_IN_FLIGHT: usize = 8;
/// a request without data is asked again
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// ftDataMultiplex::locked_handleServerRequest(): larger requests are refused
const MAX_REQUEST: u32 = 10 * 1024 * 1024;

pub struct FileTransfer {
    rx: UnboundedReceiver<Intercom>,
    core: Arc<DataCore>,
    core_tx: UnboundedSender<Intercom>,
    /// results of the final checks: (hash, ok)
    checks: (UnboundedSender<(String, bool)>, UnboundedReceiver<(String, bool)>),
    /// failed checks per download
    check_failures: HashMap<String, u32>,
}

fn file_item(size: u64, hash: &Hash) -> Vec<u8> {
    let mut v = TLV_TYPE_FILEITEM.to_be_bytes().to_vec();
    v.extend(34u32.to_be_bytes());
    v.extend(size.to_be_bytes());
    v.extend(hash);
    v
}

/// (size, hash, length of the TLV) of a RsTlvFileItem
fn parse_file_item(d: &[u8]) -> Option<(u64, Hash, usize)> {
    if u16::from_be_bytes(d.get(0..2)?.try_into().ok()?) != TLV_TYPE_FILEITEM {
        return None;
    }
    let len = u32::from_be_bytes(d.get(2..6)?.try_into().ok()?) as usize;
    let size = u64::from_be_bytes(d.get(6..14)?.try_into().ok()?);
    let hash: Hash = d.get(14..34)?.try_into().ok()?;
    (len >= 34 && d.len() >= len).then_some((size, hash, len))
}

fn data_item(size: u64, hash: &Hash, offset: u64, data: &[u8]) -> Vec<u8> {
    let fi = file_item(size, hash);
    let total = 6 + fi.len() + 14 + 6 + data.len();
    let mut v = Vec::with_capacity(total);
    v.extend(TLV_TYPE_FILEDATA.to_be_bytes());
    v.extend((total as u32).to_be_bytes());
    v.extend(fi);
    v.extend(TLV_TYPE_UINT64_OFFSET.to_be_bytes());
    v.extend(14u32.to_be_bytes());
    v.extend(offset.to_be_bytes());
    v.extend(TLV_TYPE_BIN_FILEDATA.to_be_bytes());
    v.extend(((6 + data.len()) as u32).to_be_bytes());
    v.extend(data);
    v
}

/// (size, hash, offset, data) of a RsTlvFileData
fn parse_data_item(d: &[u8]) -> Option<(u64, Hash, u64, &[u8])> {
    if u16::from_be_bytes(d.get(0..2)?.try_into().ok()?) != TLV_TYPE_FILEDATA {
        return None;
    }
    let total = u32::from_be_bytes(d.get(2..6)?.try_into().ok()?) as usize;
    let d = d.get(..total)?;
    let (size, hash, fl) = parse_file_item(d.get(6..)?)?;
    let mut at = 6 + fl;
    let mut offset = 0;
    let mut data: &[u8] = &[];
    while at + 6 <= d.len() {
        let ty = u16::from_be_bytes(d[at..at + 2].try_into().ok()?);
        let len = u32::from_be_bytes(d[at + 2..at + 6].try_into().ok()?) as usize;
        let v = d.get(at + 6..at + len)?;
        match ty {
            TLV_TYPE_UINT64_OFFSET => offset = u64::from_be_bytes(v.try_into().ok()?),
            TLV_TYPE_BIN_FILEDATA => data = v,
            _ => {}
        }
        at += len.max(6);
    }
    Some((size, hash, offset, data))
}

fn map_payload(is_client: bool, hash: &Hash, map: &[u32]) -> Vec<u8> {
    let mut v = vec![is_client as u8];
    v.extend(hash);
    v.extend((map.len() as u32).to_be_bytes());
    for w in map {
        v.extend(w.to_be_bytes());
    }
    v
}

impl FileTransfer {
    pub async fn new(core: &Arc<DataCore>, core_tx: UnboundedSender<Intercom>, rx: UnboundedReceiver<Intercom>) -> Self {
        FileTransfer { rx, core: core.to_owned(), core_tx, checks: unbounded_channel(), check_failures: HashMap::new() }
    }

    fn send(core_tx: &UnboundedSender<Intercom>, peer: Arc<SslId>, sub_type: u8, payload: Vec<u8>) {
        let header = ServiceHeader::new(ServiceType::FileTransfer, sub_type, &payload);
        let _ = core_tx.send(Intercom::Send(Packet::new(header.into(), payload, peer)));
    }

    fn handle_incoming(&mut self, packet: Packet) {
        let header: ServiceHeader = packet.header.to_owned().into();
        let d = &packet.payload;
        let peer = packet.peer_id.clone();
        match header.sub_type {
            SUB_DATA_REQUEST => {
                let parsed = (|| {
                    let offset = u64::from_be_bytes(d.get(0..8)?.try_into().ok()?);
                    let size = u32::from_be_bytes(d.get(8..12)?.try_into().ok()?);
                    let (_, hash, _) = parse_file_item(d.get(12..)?)?;
                    Some((offset, size, hash))
                })();
                match parsed {
                    Some((offset, size, hash)) => self.serve_data(peer, hash, offset, size),
                    None => warn!("[ft] broken data request from {peer}"),
                }
            }
            SUB_DATA => match parse_data_item(d) {
                Some((_, hash, offset, data)) => self.recv_data(&peer.to_string(), &hash, offset, data),
                None => warn!("[ft] broken data item from {peer}"),
            },
            SUB_CHUNK_MAP_REQUEST => {
                let (Some(is_client), Some(hash)) = (d.first().map(|b| *b != 0), d.get(1..21).and_then(|h| Hash::try_from(h).ok())) else {
                    return warn!("[ft] broken chunk map request from {peer}");
                };
                self.chunk_map_request(peer, is_client, &hash);
            }
            SUB_CHUNK_MAP => {
                let parsed = (|| {
                    let is_client = *d.first()? != 0;
                    let hash: Hash = d.get(1..21)?.try_into().ok()?;
                    let n = u32::from_be_bytes(d.get(21..25)?.try_into().ok()?) as usize;
                    let mut map = vec![];
                    for i in 0..n.min(1 << 20) {
                        map.push(u32::from_be_bytes(d.get(25 + 4 * i..29 + 4 * i)?.try_into().ok()?));
                    }
                    Some((is_client, hash, map))
                })();
                let Some((is_client, hash, map)) = parsed else {
                    return warn!("[ft] broken chunk map from {peer}");
                };
                // the map of a source (for us as the client)
                if is_client {
                    if let Some(mut f) = files::files() {
                        if let Some(dl) = f.downloads.get_mut(&hash_hex(&hash)) {
                            dl.runtime.source_maps.insert(peer.to_string(), map);
                        }
                    }
                }
            }
            SUB_CHUNK_CRC_REQUEST => {
                let parsed = (|| {
                    let hash: Hash = d.get(0..20)?.try_into().ok()?;
                    let chunk = u32::from_be_bytes(d.get(20..24)?.try_into().ok()?);
                    Some((hash, chunk))
                })();
                if let Some((hash, chunk)) = parsed {
                    self.serve_crc(peer, hash, chunk);
                }
            }
            SUB_CHUNK_CRC => trace!("[ft] chunk CRC from {peer} (not used)"),
            other => trace!("[ft] ignoring sub type {other:#04x} from {peer}"),
        }
    }

    /// the file a friend may get: one of our shared files
    fn source_file(hash: &Hash) -> Option<(PathBuf, u64, String)> {
        files::files()?.local.friend_file(hash)
    }

    /// ftDataMultiplex::handleRecvDataRequest() / locked_handleServerRequest() + ftServer::sendData()
    fn serve_data(&self, peer: Arc<SslId>, hash: Hash, offset: u64, size: u32) {
        if size > MAX_REQUEST {
            return warn!("[ft] {peer} asks a too large part ({size} bytes)");
        }
        let Some((path, file_size, name)) = Self::source_file(&hash) else {
            return debug!("[ft] {peer} asks {} which we don't share", hash_hex(&hash));
        };
        if offset >= file_size {
            return;
        }
        let core_tx = self.core_tx.clone();
        tokio::task::spawn_blocking(move || {
            let len = (size as u64).min(file_size - offset) as usize;
            let data = match files::read_part(&path, offset, len) {
                Ok(d) => d,
                Err(e) => return warn!("[ft] can't read {}: {e}", path.display()),
            };
            let mut at = 0;
            while at < data.len() {
                let end = (at + MAX_FT_CHUNK).min(data.len());
                let payload = data_item(file_size, &hash, offset + at as u64, &data[at..end]);
                Self::send(&core_tx, peer.clone(), SUB_DATA, payload);
                at = end;
            }
            if let Some(mut f) = files::files() {
                let key = (peer.to_string(), hash_hex(&hash));
                let up = f.uploads.entry(key).or_insert_with(|| Upload {
                    peer: peer.to_string(),
                    hash: hash_hex(&hash),
                    name,
                    size: file_size,
                    sent: 0,
                    last: 0,
                    recent: vec![],
                });
                up.sent += data.len() as u64;
                up.last = now();
                up.recent.push((Instant::now(), data.len() as u64));
                let cutoff = Instant::now() - Duration::from_secs(10);
                up.recent.retain(|(t, _)| *t > cutoff);
            }
        });
    }

    /// ftDataMultiplex::handleRecvServerChunkMapRequest() / handleRecvClientChunkMapRequest()
    fn chunk_map_request(&self, peer: Arc<SslId>, is_client: bool, hash: &Hash) {
        if !is_client {
            // a client asks what we have: everything
            let Some((_, size, _)) = Self::source_file(hash) else { return };
            let chunks = files::chunk_count(size);
            let mut map = vec![0u32; ((chunks + 31) / 32) as usize];
            for c in 0..chunks {
                map[(c >> 5) as usize] |= 1 << (c & 31);
            }
            Self::send(&self.core_tx, peer, SUB_CHUNK_MAP, map_payload(true, hash, &map));
        } else {
            // a source asks how far our download is
            let map = files::files().and_then(|f| f.downloads.get(&hash_hex(hash)).map(|d| d.done.clone()));
            if let Some(map) = map {
                Self::send(&self.core_tx, peer, SUB_CHUNK_MAP, map_payload(false, hash, &map));
            }
        }
    }

    /// ftDataMultiplex::handleRecvChunkCrcRequest()
    fn serve_crc(&self, peer: Arc<SslId>, hash: Hash, chunk: u32) {
        let Some((path, size, _)) = Self::source_file(&hash) else { return };
        let core_tx = self.core_tx.clone();
        tokio::task::spawn_blocking(move || {
            let len = chunk_len(size, chunk) as usize;
            let Ok(data) = files::read_part(&path, chunk as u64 * CHUNK_SIZE, len) else { return };
            let mut p = hash.to_vec();
            p.extend(chunk.to_be_bytes());
            p.extend(openssl::sha::sha1(&data));
            Self::send(&core_tx, peer, SUB_CHUNK_CRC, p);
        });
    }

    /// ftTransferModule::recvFileData()
    fn recv_data(&self, peer: &str, hash: &Hash, offset: u64, data: &[u8]) {
        let Some(mut f) = files::files() else { return };
        let partials = f.config.partials_dir.clone();
        let key = hash_hex(hash);
        let Some(dl) = f.downloads.get_mut(&key) else {
            return trace!("[ft] data for {key} which we don't download");
        };
        if !matches!(dl.state, files::DL_DOWNLOADING | files::DL_WAITING) || data.is_empty() || offset >= dl.size {
            return;
        }
        let end = (offset + data.len() as u64).min(dl.size);
        let data = &data[..(end - offset) as usize];
        let path = dl.partial_path(&partials);
        if let Err(e) = files::write_part(&path, offset, data) {
            dl.state = files::DL_FAILED;
            dl.error = format!("can't write {}: {e}", path.display());
            warn!("[ft] {}", dl.error);
            return;
        }
        dl.runtime.recent.push((Instant::now(), data.len() as u64));
        let cutoff = Instant::now() - Duration::from_secs(10);
        dl.runtime.recent.retain(|(t, _)| *t > cutoff);
        dl.runtime.in_flight.retain(|(o, s, p, _)| !(p == peer && *o <= offset && end >= *o + *s as u64));
        // the received range, per chunk
        let mut at = offset;
        while at < end {
            let c = (at / CHUNK_SIZE) as u32;
            let c_start = c as u64 * CHUNK_SIZE;
            let c_end = c_start + chunk_len(dl.size, c);
            let piece_end = end.min(c_end);
            if !dl.is_done(c) {
                let r = dl.runtime.received.entry(c).or_default();
                add_range(r, at, piece_end);
                if r.len() == 1 && r[0] == (c_start, c_end) {
                    dl.runtime.received.remove(&c);
                    dl.set_done(c);
                }
            }
            at = piece_end;
        }
        f.save_downloads(false);
    }

    /// ftTransferModule::tick(): keeps a few requests on their way for every download
    async fn tick(&mut self) {
        let connected: HashMap<String, Arc<SslId>> =
            self.core.get_connected_peers().lock().await.0.keys().map(|p| (p.to_string(), p.clone())).collect();
        let mut requests = vec![];
        let mut map_requests = vec![];
        let mut checks = vec![];
        {
            let Some(mut f) = files::files() else { return };
            let t = now();
            f.uploads.retain(|_, u| u.last + 600 > t);
            let partials = f.config.partials_dir.clone();
            for dl in f.downloads.values_mut() {
                if !matches!(dl.state, files::DL_DOWNLOADING | files::DL_WAITING) {
                    continue;
                }
                if dl.size == 0 || dl.all_done() {
                    if dl.runtime.in_flight.is_empty() {
                        dl.state = files::DL_CHECKING;
                        checks.push((dl.hash.clone(), PathBuf::from(&partials).join(&dl.hash), dl.size));
                    }
                    continue;
                }
                let online: Vec<String> = dl.sources.iter().filter(|s| connected.contains_key(*s)).cloned().collect();
                dl.state = if online.is_empty() { files::DL_WAITING } else { files::DL_DOWNLOADING };
                if online.is_empty() {
                    dl.runtime.in_flight.clear();
                    continue;
                }
                // ask the sources what they have, once
                let Some(hash) = files::parse_hash(&dl.hash) else { continue };
                for s in &online {
                    if dl.runtime.map_asked.insert(s.clone()) {
                        map_requests.push((connected[s].clone(), hash));
                    }
                }
                let now_i = Instant::now();
                dl.runtime.in_flight.retain(|(_, _, p, at)| now_i.duration_since(*at) < REQUEST_TIMEOUT && online.contains(p));
                let mut next_source = dl.runtime.in_flight.len();
                'chunks: for c in 0..dl.chunks() {
                    if dl.runtime.in_flight.len() >= MAX_IN_FLIGHT {
                        break;
                    }
                    if dl.is_done(c) {
                        continue;
                    }
                    let c_start = c as u64 * CHUNK_SIZE;
                    let c_end = c_start + chunk_len(dl.size, c);
                    // what is already here or on its way
                    let mut covered = dl.runtime.received.get(&c).cloned().unwrap_or_default();
                    for (o, s, _, _) in &dl.runtime.in_flight {
                        let (a, b) = (*o, *o + *s as u64);
                        if b > c_start && a < c_end {
                            add_range(&mut covered, a.max(c_start), b.min(c_end));
                        }
                    }
                    // sources that have this chunk (no map yet: assume all)
                    let have: Vec<&String> = online
                        .iter()
                        .filter(|s| {
                            dl.runtime
                                .source_maps
                                .get(*s)
                                .map(|m| m.get((c >> 5) as usize).map(|w| w & (1 << (c & 31)) != 0).unwrap_or(false))
                                .unwrap_or(true)
                        })
                        .collect();
                    if have.is_empty() {
                        continue;
                    }
                    let mut at = c_start;
                    for (a, b) in covered.iter().copied().chain(std::iter::once((c_end, c_end))) {
                        while at < a {
                            if dl.runtime.in_flight.len() >= MAX_IN_FLIGHT {
                                break 'chunks;
                            }
                            let size = (a - at).min(SLICE) as u32;
                            let source = have[next_source % have.len()].clone();
                            next_source += 1;
                            dl.runtime.in_flight.push((at, size, source.clone(), now_i));
                            requests.push((connected[&source].clone(), hash, dl.size, at, size));
                            at += size as u64;
                        }
                        at = at.max(b);
                    }
                }
            }
        }
        for (peer, hash) in map_requests {
            let mut p = vec![0u8]; // is_client = false: the request is for a server's map
            p.extend(hash);
            Self::send(&self.core_tx, peer, SUB_CHUNK_MAP_REQUEST, p);
        }
        for (peer, hash, size, offset, chunk) in requests {
            let mut p = offset.to_be_bytes().to_vec();
            p.extend(chunk.to_be_bytes());
            p.extend(file_item(size, &hash));
            Self::send(&self.core_tx, peer, SUB_DATA_REQUEST, p);
        }
        for (hash, path, size) in checks {
            info!("[ft] {hash}: all data here, checking");
            let tx = self.checks.0.clone();
            tokio::task::spawn_blocking(move || {
                let ok = if size == 0 {
                    let _ = std::fs::write(&path, []);
                    hash == hash_hex(&openssl::sha::sha1(&[]))
                } else {
                    files::hash_file(&path, |_| {}).map(|h| hash_hex(&h) == hash).unwrap_or(false)
                };
                let _ = tx.send((hash, ok));
            });
        }
    }

    /// ftController::completeFile(): move the checked file to the download folder
    fn check_done(&mut self, hash: String, ok: bool) {
        let Some(mut f) = files::files() else { return };
        let download_dir = f.config.download_dir.clone();
        let partials = f.config.partials_dir.clone();
        let Some(dl) = f.downloads.get_mut(&hash) else { return };
        if !ok {
            let n = self.check_failures.entry(hash.clone()).or_default();
            *n += 1;
            dl.done.clear();
            dl.runtime = Default::default();
            if *n >= 3 {
                dl.state = files::DL_FAILED;
                dl.error = "the data never matches the file hash".to_owned();
            } else {
                dl.state = files::DL_DOWNLOADING;
                dl.error = "the data didn't match the file hash, downloading again".to_owned();
            }
            warn!("[ft] {hash}: {}", dl.error);
            f.save_downloads(true);
            return;
        }
        // optional sub folder (when a whole folder was downloaded)
        let mut dir = PathBuf::from(&download_dir);
        for part in dl.dest_dir.split(['/', '\\']).filter(|p| !p.is_empty()) {
            dir.push(files::sanitize_name(part));
        }
        let _ = std::fs::create_dir_all(&dir);
        let target = files::free_path(&dir, &dl.name);
        let partial = dl.partial_path(&partials);
        let moved = std::fs::rename(&partial, &target).or_else(|_| {
            std::fs::copy(&partial, &target).and_then(|_| std::fs::remove_file(&partial))
        });
        match moved {
            Ok(()) => {
                dl.state = files::DL_COMPLETE;
                dl.completed = now();
                dl.path = target.display().to_string();
                dl.error.clear();
                dl.runtime = Default::default();
                info!("[ft] downloaded {}", target.display());
            }
            Err(e) => {
                dl.state = files::DL_FAILED;
                dl.error = format!("can't move the file to {}: {e}", target.display());
                warn!("[ft] {}", dl.error);
            }
        }
        f.save_downloads(true);
    }
}

#[async_trait]
impl Service for FileTransfer {
    fn get_id(&self) -> ServiceType {
        ServiceType::FileTransfer
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "ft")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!("[ft] service started");
            let mut timer = interval(Duration::from_millis(250));
            loop {
                select! {
                    msg = self.rx.recv() => {
                        match msg {
                            Some(Intercom::Receive(packet)) => self.handle_incoming(packet),
                            Some(_) => {}
                            None => break,
                        }
                    }
                    Some((hash, ok)) = self.checks.1.recv() => self.check_done(hash, ok),
                    _ = files::transfers_wait() => self.tick().await,
                    _ = timer.tick() => self.tick().await,
                }
            }
        })
    }
}
