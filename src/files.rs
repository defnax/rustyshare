//! File sharing, like libretroshare's `file_sharing/` (p3FileDatabase) and `ft/` (ftServer):
//!
//! - shared folders (`SharedDirInfo`: real path, virtual name, DIR_FLAGS_*), hashed with
//!   SHA1 over the whole file (the RetroShare file hash); hashes are cached by path,
//!   size and modification time
//! - our directory tree as friends see it: the root (null hash) holds the shared folders,
//!   every folder has a hash H(salt | parent hash | name) and a "recursive modification
//!   time" that changes whenever something below changes (friends compare it)
//! - friends' trees, filled by the file list service (0x0019) one folder at a time
//! - downloads (1 MB chunks, partial file in the partials folder, moved to the download
//!   folder once the SHA1 matches) and uploads, used by the file transfer service (0x0017)

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, OnceLock},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

pub type Hash = [u8; 20];
pub const NULL_HASH: Hash = [0; 20];

// FileStorageFlags (retroshare/rstypes.h)
pub const DIR_FLAGS_ANONYMOUS_DOWNLOAD: u32 = 0x0080;
pub const DIR_FLAGS_BROWSABLE: u32 = 0x0400;
pub const DIR_FLAGS_ANONYMOUS_SEARCH: u32 = 0x0800;

/// ChunkMap::CHUNKMAP_FIXED_CHUNK_SIZE
pub const CHUNK_SIZE: u64 = 1024 * 1024;

const CONFIG_FILE: &str = "rustyshare_files.json";
const HASH_CACHE_FILE: &str = "rustyshare_hash_cache.json";
const DOWNLOADS_FILE: &str = "rustyshare_downloads.json";

/// how often the shared folders are checked for changes (RetroShare's default watch period)
const RESCAN_SECS: u64 = 10 * 60;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

pub fn hash_hex(h: &Hash) -> String {
    hex::encode(h)
}

pub fn parse_hash(s: &str) -> Option<Hash> {
    let b = hex::decode(s.trim()).ok()?;
    b.try_into().ok()
}

fn sha1(data: &[u8]) -> Hash {
    openssl::sha::sha1(data)
}

// --- configuration ----------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SharedDir {
    /// real path on this computer
    pub path: String,
    /// the name friends see
    pub virtual_name: String,
    /// DIR_FLAGS_*
    pub flags: u32,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub shared: Vec<SharedDir>,
    pub download_dir: String,
    pub partials_dir: String,
    /// random salt of the folder hashes (kept, so friends' references stay valid)
    pub salt: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct CacheEntry {
    size: u64,
    mtime: u64,
    hash: String,
}

#[derive(Serialize, Deserialize, Default)]
struct HashCache {
    files: HashMap<String, CacheEntry>,
    /// per folder hash: (content digest, recursive modification time)
    dirs: HashMap<String, (String, u32)>,
}

// --- our tree ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct LocalFile {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
    pub hash: Hash,
    pub mtime: u32,
}

#[derive(Clone, Debug)]
pub struct LocalDir {
    pub hash: Hash,
    /// virtual name for shared folders, real name below
    pub name: String,
    pub path: PathBuf,
    pub mtime: u32,
    pub recurs: u32,
    pub parent: usize,
    pub subdirs: Vec<usize>,
    pub files: Vec<LocalFile>,
    /// DIR_FLAGS_* of the shared folder this is in
    pub flags: u32,
}

#[derive(Default, Clone)]
pub struct LocalTree {
    /// index 0 is the root
    pub dirs: Vec<LocalDir>,
    pub by_hash: HashMap<Hash, usize>,
    /// file hash -> (path, size, name, DIR_FLAGS_*)
    pub files: HashMap<Hash, (PathBuf, u64, String, u32)>,
    pub total_files: u64,
    pub total_size: u64,
}

impl LocalTree {
    /// FileListIO serialisation of a folder for a friend (LocalDirectoryStorage::serialiseDirEntry())
    pub fn serialise_dir(&self, index: usize) -> Option<Vec<u8>> {
        let dir = self.dirs.get(index)?;
        let mut out = vec![];
        fl_string(&mut out, TAG_DIR_NAME, if index == 0 { "" } else { &dir.name });
        fl_u32(&mut out, TAG_RECURS_MODIF_TS, dir.recurs);
        fl_u32(&mut out, TAG_MODIF_TS, dir.mtime);
        // at the root only the browsable shared folders
        let subdirs: Vec<&LocalDir> = dir
            .subdirs
            .iter()
            .filter_map(|i| self.dirs.get(*i))
            .filter(|d| index != 0 || d.flags & DIR_FLAGS_BROWSABLE != 0)
            .collect();
        fl_u32(&mut out, TAG_RAW_NUMBER, subdirs.len() as u32);
        fl_u32(&mut out, TAG_RAW_NUMBER, dir.files.len() as u32);
        for d in &subdirs {
            fl_field(&mut out, TAG_ENTRY_INDEX, &d.hash);
        }
        for f in &dir.files {
            let mut fs = vec![];
            fl_string(&mut fs, TAG_FILE_NAME, &f.name);
            fl_field(&mut fs, TAG_FILE_SIZE, &f.size.to_be_bytes());
            fl_field(&mut fs, TAG_FILE_SHA1_HASH, &f.hash);
            fl_u32(&mut fs, TAG_MODIF_TS, f.mtime);
            fl_field(&mut out, TAG_REMOTE_FILE_ENTRY, &fs);
        }
        Some(out)
    }

    /// whether a friend may download this file (shared with friends)
    pub fn friend_file(&self, hash: &Hash) -> Option<(PathBuf, u64, String)> {
        let (path, size, name, flags) = self.files.get(hash)?;
        (flags & (DIR_FLAGS_BROWSABLE | DIR_FLAGS_ANONYMOUS_DOWNLOAD) != 0).then(|| (path.clone(), *size, name.clone()))
    }
}

// --- FileListIO (file_sharing/filelist_io.h) -----------------------------------------------

pub const TAG_FILE_SHA1_HASH: u8 = 0x20;
pub const TAG_FILE_NAME: u8 = 0x21;
pub const TAG_FILE_SIZE: u8 = 0x22;
pub const TAG_MODIF_TS: u8 = 0x30;
pub const TAG_RECURS_MODIF_TS: u8 = 0x31;
pub const TAG_ENTRY_INDEX: u8 = 0x40;
pub const TAG_DIR_NAME: u8 = 0x51;
pub const TAG_REMOTE_FILE_ENTRY: u8 = 0x13;
pub const TAG_RAW_NUMBER: u8 = 0x62;

/// FileListIO::write125Size()
fn fl_size(out: &mut Vec<u8>, s: u32) {
    if s < 192 {
        out.push(s as u8);
    } else if s < 8384 {
        let b1 = ((s - 192) & 0xff) as u8;
        let b0 = (((s - 192 - b1 as u32) >> 8) + 192) as u8;
        out.push(b0);
        out.push(b1);
    } else {
        out.push(0xff);
        out.extend(s.to_be_bytes());
    }
}

fn fl_field(out: &mut Vec<u8>, tag: u8, data: &[u8]) {
    out.push(tag);
    fl_size(out, data.len() as u32);
    out.extend(data);
}

fn fl_u32(out: &mut Vec<u8>, tag: u8, v: u32) {
    fl_field(out, tag, &v.to_be_bytes());
}

/// strings are u32 length + bytes (setRawString)
fn fl_string(out: &mut Vec<u8>, tag: u8, s: &str) {
    let mut d = (s.len() as u32).to_be_bytes().to_vec();
    d.extend(s.as_bytes());
    fl_field(out, tag, &d);
}

struct FlReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> FlReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        FlReader { data, pos: 0 }
    }

    /// FileListIO::read125Size()
    fn size(&mut self) -> Option<usize> {
        let b1 = *self.data.get(self.pos)?;
        self.pos += 1;
        if b1 < 192 {
            return Some(b1 as usize);
        }
        let b2 = *self.data.get(self.pos)?;
        self.pos += 1;
        if b1 < 224 {
            return Some((((b1 as usize) - 192) << 8) + b2 as usize + 192);
        }
        if b1 != 0xff {
            return None;
        }
        let rest = self.data.get(self.pos..self.pos + 3)?;
        self.pos += 3;
        Some(u32::from_be_bytes([b2, rest[0], rest[1], rest[2]]) as usize)
    }

    fn field(&mut self, tag: u8) -> Option<&'a [u8]> {
        if *self.data.get(self.pos)? != tag {
            return None;
        }
        self.pos += 1;
        let len = self.size()?;
        let d = self.data.get(self.pos..self.pos + len)?;
        self.pos += len;
        Some(d)
    }

    fn u32(&mut self, tag: u8) -> Option<u32> {
        Some(u32::from_be_bytes(self.field(tag)?.try_into().ok()?))
    }

    fn u64(&mut self, tag: u8) -> Option<u64> {
        Some(u64::from_be_bytes(self.field(tag)?.try_into().ok()?))
    }

    fn string(&mut self, tag: u8) -> Option<String> {
        let d = self.field(tag)?;
        let len = u32::from_be_bytes(d.get(..4)?.try_into().ok()?) as usize;
        Some(String::from_utf8_lossy(d.get(4..4 + len)?).into_owned())
    }

    fn hash(&mut self, tag: u8) -> Option<Hash> {
        self.field(tag)?.try_into().ok()
    }
}

// --- friends' trees -----------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct RemoteFile {
    pub name: String,
    pub size: u64,
    #[serde(serialize_with = "ser_hash")]
    pub hash: Hash,
    pub mtime: u32,
}

fn ser_hash<S: serde::Serializer>(h: &Hash, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hash_hex(h))
}

#[derive(Clone, Debug, Default)]
pub struct RemoteDir {
    pub name: String,
    pub recurs: u32,
    pub mtime: u32,
    /// local time of the last answer, 0: never fetched
    pub updated: u64,
    pub parent: Option<Hash>,
    pub subdirs: Vec<Hash>,
    pub files: Vec<RemoteFile>,
}

#[derive(Default)]
pub struct RemoteTree {
    pub dirs: HashMap<Hash, RemoteDir>,
    /// request id -> (folder hash, sent at)
    pub pending: HashMap<u64, (Hash, u64)>,
    /// responses in several parts: request id -> (checksum, data so far)
    pub partial: HashMap<u64, (Hash, Vec<u8>)>,
}

impl RemoteTree {
    pub fn new() -> Self {
        let mut t = RemoteTree::default();
        t.dirs.insert(NULL_HASH, RemoteDir::default());
        t
    }

    /// RemoteDirectoryStorage::deserialiseUpdateDirEntry() + updateDirEntry()
    pub fn update_dir(&mut self, hash: &Hash, data: &[u8]) -> bool {
        let mut r = FlReader::new(data);
        let parsed = (|| {
            let name = r.string(TAG_DIR_NAME)?;
            let recurs = r.u32(TAG_RECURS_MODIF_TS)?;
            let mtime = r.u32(TAG_MODIF_TS)?;
            let n_dirs = r.u32(TAG_RAW_NUMBER)?;
            let n_files = r.u32(TAG_RAW_NUMBER)?;
            let mut subdirs = vec![];
            for _ in 0..n_dirs {
                subdirs.push(r.hash(TAG_ENTRY_INDEX)?);
            }
            let mut files = vec![];
            for _ in 0..n_files {
                let mut f = FlReader::new(r.field(TAG_REMOTE_FILE_ENTRY)?);
                files.push(RemoteFile {
                    name: f.string(TAG_FILE_NAME)?,
                    size: f.u64(TAG_FILE_SIZE)?,
                    hash: f.hash(TAG_FILE_SHA1_HASH)?,
                    mtime: f.u32(TAG_MODIF_TS)?,
                });
            }
            Some((name, recurs, mtime, subdirs, files))
        })();
        let Some((name, recurs, mtime, subdirs, files)) = parsed else {
            return false;
        };
        let Some(old) = self.dirs.get(hash) else { return false };
        let removed: Vec<Hash> = old.subdirs.iter().filter(|h| !subdirs.contains(h)).copied().collect();
        for h in removed {
            self.remove_below(&h);
        }
        for h in &subdirs {
            self.dirs.entry(*h).or_insert_with(|| RemoteDir { parent: Some(*hash), ..Default::default() });
        }
        let d = self.dirs.get_mut(hash).expect("checked above");
        d.name = name;
        d.recurs = recurs;
        d.mtime = mtime;
        d.updated = now();
        d.subdirs = subdirs;
        d.files = files;
        true
    }

    fn remove_below(&mut self, hash: &Hash) {
        if let Some(d) = self.dirs.remove(hash) {
            for s in d.subdirs {
                self.remove_below(&s);
            }
        }
    }

    /// the friend says the folder is gone
    pub fn remove_dir(&mut self, hash: &Hash) {
        if *hash == NULL_HASH {
            let subs = self.dirs.get(hash).map(|d| d.subdirs.clone()).unwrap_or_default();
            for s in subs {
                self.remove_below(&s);
            }
            self.dirs.insert(NULL_HASH, RemoteDir { updated: now(), ..Default::default() });
            return;
        }
        let parent = self.dirs.get(hash).and_then(|d| d.parent);
        self.remove_below(hash);
        if let Some(p) = parent.and_then(|p| self.dirs.get_mut(&p)) {
            p.subdirs.retain(|h| h != hash);
        }
    }

    pub fn file_count(&self) -> (u64, u64) {
        self.dirs.values().flat_map(|d| d.files.iter()).fold((0, 0), |(n, s), f| (n + 1, s + f.size))
    }
}

// --- downloads and uploads ------------------------------------------------------------------

pub const DL_DOWNLOADING: u8 = 0;
pub const DL_PAUSED: u8 = 1;
pub const DL_CHECKING: u8 = 2;
pub const DL_COMPLETE: u8 = 3;
pub const DL_FAILED: u8 = 4;
/// waiting: no source online
pub const DL_WAITING: u8 = 5;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Download {
    pub hash: String,
    pub name: String,
    pub size: u64,
    /// friend nodes that have the file
    pub sources: Vec<String>,
    /// one bit per chunk, like CompressedChunkMap
    pub done: Vec<u32>,
    pub state: u8,
    pub added: u64,
    #[serde(default)]
    pub completed: u64,
    /// where the finished file is
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub error: String,
    /// sub folder in the download folder (from a friend's folder)
    #[serde(default)]
    pub dest_dir: String,

    #[serde(skip)]
    pub runtime: DownloadRuntime,
}

#[derive(Default, Clone, Debug)]
pub struct DownloadRuntime {
    /// (offset, size, source, sent at)
    pub in_flight: Vec<(u64, u32, String, Instant)>,
    /// bytes received per unfinished chunk: sorted, merged ranges
    pub received: HashMap<u32, Vec<(u64, u64)>>,
    /// chunk maps of the sources (None: not known yet, assume complete)
    pub source_maps: HashMap<String, Vec<u32>>,
    /// (time, bytes) of the last seconds, for the rate
    pub recent: Vec<(Instant, u64)>,
    pub map_asked: HashSet<String>,
}

impl Download {
    pub fn chunks(&self) -> u32 {
        chunk_count(self.size)
    }

    pub fn is_done(&self, chunk: u32) -> bool {
        self.done.get((chunk >> 5) as usize).map(|w| w & (1 << (chunk & 31)) != 0).unwrap_or(false)
    }

    pub fn set_done(&mut self, chunk: u32) {
        let i = (chunk >> 5) as usize;
        if self.done.len() <= i {
            self.done.resize(i + 1, 0);
        }
        self.done[i] |= 1 << (chunk & 31);
    }

    pub fn done_bytes(&self) -> u64 {
        let mut total = 0;
        for c in 0..self.chunks() {
            if self.is_done(c) {
                total += chunk_len(self.size, c);
            } else if let Some(r) = self.runtime.received.get(&c) {
                total += r.iter().map(|(a, b)| b - a).sum::<u64>();
            }
        }
        total
    }

    pub fn rate(&self) -> f64 {
        let cutoff = Instant::now() - std::time::Duration::from_secs(5);
        let bytes: u64 = self.runtime.recent.iter().filter(|(t, _)| *t > cutoff).map(|(_, b)| b).sum();
        bytes as f64 / 5.0
    }

    pub fn all_done(&self) -> bool {
        (0..self.chunks()).all(|c| self.is_done(c))
    }

    /// the file being downloaded (in the partials folder)
    pub fn partial_path(&self, partials_dir: &str) -> PathBuf {
        PathBuf::from(partials_dir).join(&self.hash)
    }
}

pub fn chunk_count(size: u64) -> u32 {
    ((size + CHUNK_SIZE - 1) / CHUNK_SIZE).max(1) as u32
}

pub fn chunk_len(size: u64, chunk: u32) -> u64 {
    let start = chunk as u64 * CHUNK_SIZE;
    (size.saturating_sub(start)).min(CHUNK_SIZE)
}

/// adds [a, b) to sorted, merged ranges
pub fn add_range(ranges: &mut Vec<(u64, u64)>, a: u64, b: u64) {
    ranges.push((a, b));
    ranges.sort();
    let mut merged: Vec<(u64, u64)> = vec![];
    for (s, e) in ranges.drain(..) {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    *ranges = merged;
}

#[derive(Clone, Debug, Serialize)]
pub struct Upload {
    pub peer: String,
    pub hash: String,
    pub name: String,
    pub size: u64,
    pub sent: u64,
    pub last: u64,
    #[serde(skip)]
    pub recent: Vec<(Instant, u64)>,
}

impl Upload {
    pub fn rate(&self) -> f64 {
        let cutoff = Instant::now() - std::time::Duration::from_secs(5);
        let bytes: u64 = self.recent.iter().filter(|(t, _)| *t > cutoff).map(|(_, b)| b).sum();
        bytes as f64 / 5.0
    }
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct HashingStatus {
    pub file: String,
    pub done: usize,
    pub total: usize,
}

// --- the store --------------------------------------------------------------------------

pub struct Files {
    config_dir: PathBuf,
    pub config: Config,
    pub local: LocalTree,
    pub remote: HashMap<String, RemoteTree>,
    pub downloads: BTreeMap<String, Download>,
    pub uploads: HashMap<(String, String), Upload>,
    pub hashing: Option<HashingStatus>,
    pub scanning: bool,
    downloads_saved: Option<Instant>,
}

static FILES: OnceLock<Mutex<Files>> = OnceLock::new();
static RESCAN: OnceLock<Notify> = OnceLock::new();
static TRANSFER: OnceLock<Notify> = OnceLock::new();

/// The file sharing store (None before `load`).
pub fn files() -> Option<MutexGuard<'static, Files>> {
    FILES.get().map(|m| m.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Wakes the scanner (shared folders changed).
pub fn rescan() {
    RESCAN.get_or_init(Notify::new).notify_one();
}

/// Wakes the transfer service (download added, resumed, ...).
pub fn transfers_changed() {
    TRANSFER.get_or_init(Notify::new).notify_one();
}

pub async fn transfers_wait() {
    TRANSFER.get_or_init(Notify::new).notified().await
}

/// Loads the configuration and the downloads and starts the folder scanner.
/// `location_dir` is the location's folder (Downloads and Partials go there by default).
pub fn load(config_dir: PathBuf, location_dir: PathBuf) {
    let mut config: Config = fs::read(config_dir.join(CONFIG_FILE))
        .ok()
        .and_then(|d| serde_json::from_slice(&d).map_err(|e| warn!("[files] can't read {CONFIG_FILE}: {e}")).ok())
        .unwrap_or_default();
    if config.salt.is_empty() {
        use nanorand::Rng;
        let mut rng = nanorand::WyRand::new();
        let salt: Vec<u8> = (0..20).map(|_| rng.generate::<u8>()).collect();
        config.salt = hex::encode(salt);
    }
    if config.download_dir.is_empty() {
        config.download_dir = location_dir.join("Downloads").display().to_string();
    }
    if config.partials_dir.is_empty() {
        config.partials_dir = location_dir.join("Partials").display().to_string();
    }
    let _ = fs::create_dir_all(&config.download_dir);
    let _ = fs::create_dir_all(&config.partials_dir);

    let mut downloads: BTreeMap<String, Download> = fs::read(config_dir.join(DOWNLOADS_FILE))
        .ok()
        .and_then(|d| serde_json::from_slice::<Vec<Download>>(&d).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|d| (d.hash.clone(), d))
        .collect();
    // a check that was interrupted is done again
    for d in downloads.values_mut() {
        if d.state == DL_CHECKING {
            d.state = DL_DOWNLOADING;
        }
    }

    let files = Files {
        config_dir,
        config,
        local: LocalTree::default(),
        remote: HashMap::new(),
        downloads,
        uploads: HashMap::new(),
        hashing: None,
        scanning: false,
        downloads_saved: None,
    };
    files.save_config();
    if FILES.set(Mutex::new(files)).is_err() {
        return;
    }
    tokio::spawn(scanner());
}

impl Files {
    pub fn save_config(&self) {
        match serde_json::to_vec_pretty(&self.config) {
            Ok(d) => {
                if let Err(e) = fs::write(self.config_dir.join(CONFIG_FILE), d) {
                    warn!("[files] can't save {CONFIG_FILE}: {e}");
                }
            }
            Err(e) => warn!("[files] can't save {CONFIG_FILE}: {e}"),
        }
    }

    /// saves the downloads (at most every 5 s unless forced)
    pub fn save_downloads(&mut self, force: bool) {
        if !force && self.downloads_saved.map(|t| t.elapsed().as_secs() < 5).unwrap_or(false) {
            return;
        }
        self.downloads_saved = Some(Instant::now());
        let list: Vec<&Download> = self.downloads.values().collect();
        match serde_json::to_vec(&list) {
            Ok(d) => {
                if let Err(e) = fs::write(self.config_dir.join(DOWNLOADS_FILE), d) {
                    warn!("[files] can't save {DOWNLOADS_FILE}: {e}");
                }
            }
            Err(e) => warn!("[files] can't save {DOWNLOADS_FILE}: {e}"),
        }
    }

    pub fn remote_tree(&mut self, peer: &str) -> &mut RemoteTree {
        self.remote.entry(peer.to_owned()).or_insert_with(RemoteTree::new)
    }

    /// Adds a download (rsFiles::FileRequest). Returns false if it already exists.
    pub fn add_download(&mut self, hash: &str, name: &str, size: u64, sources: Vec<String>, dest_dir: &str) -> bool {
        let hash = hash.to_lowercase();
        if let Some(d) = self.downloads.get_mut(&hash) {
            // already there: more sources
            for s in sources {
                if !d.sources.contains(&s) {
                    d.sources.push(s);
                }
            }
            if d.state == DL_FAILED {
                d.state = DL_DOWNLOADING;
                d.error.clear();
            }
            return d.state != DL_COMPLETE;
        }
        let name = sanitize_name(name);
        self.downloads.insert(
            hash.clone(),
            Download {
                hash,
                name,
                size,
                sources,
                done: vec![],
                state: DL_DOWNLOADING,
                added: now(),
                completed: 0,
                path: String::new(),
                error: String::new(),
                dest_dir: dest_dir.to_owned(),
                runtime: Default::default(),
            },
        );
        self.save_downloads(true);
        transfers_changed();
        true
    }
}

/// no folders or odd characters in names coming from friends
pub fn sanitize_name(name: &str) -> String {
    let n: String = name
        .chars()
        .map(|c| if matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control() { '_' } else { c })
        .collect();
    let n = n.trim().trim_matches('.').to_owned();
    if n.is_empty() {
        "file".to_owned()
    } else {
        n
    }
}

/// a free file name in `dir` ("name (1).ext", ...)
pub fn free_path(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 1.. {
        let p = dir.join(format!("{stem} ({n}){ext}"));
        if !p.exists() {
            return p;
        }
    }
    unreachable!()
}

/// reads part of a file
pub fn read_part(path: &Path, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mut f = fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0; len];
    let mut got = 0;
    while got < len {
        let n = f.read(&mut buf[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    buf.truncate(got);
    Ok(buf)
}

pub fn write_part(path: &Path, offset: u64, data: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new().create(true).write(true).open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(data)
}

/// SHA1 of a whole file (the RetroShare file hash)
pub fn hash_file(path: &Path, mut progress: impl FnMut(u64)) -> std::io::Result<Hash> {
    let mut f = fs::File::open(path)?;
    let mut h = openssl::sha::Sha1::new();
    let mut buf = vec![0; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        progress(n as u64);
    }
    Ok(h.finish())
}

// --- scanning the shared folders --------------------------------------------------------

struct WalkDir {
    path: PathBuf,
    name: String,
    mtime: u32,
    /// (name, path, size, mtime)
    files: Vec<(String, PathBuf, u64, u64)>,
    subdirs: Vec<WalkDir>,
}

fn mtime_of(meta: &fs::Metadata) -> u64 {
    meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or_default()
}

fn walk(path: &Path, name: String, depth: u32) -> WalkDir {
    let mut w = WalkDir {
        path: path.to_owned(),
        name,
        mtime: fs::metadata(path).map(|m| mtime_of(&m) as u32).unwrap_or_default(),
        files: vec![],
        subdirs: vec![],
    };
    let Ok(entries) = fs::read_dir(path) else { return w };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        // hidden files and RetroShare's own partial downloads stay private
        if name.starts_with('.') || name.ends_with(".bak") || name.ends_with('~') {
            continue;
        }
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if depth < 64 {
                w.subdirs.push(walk(&e.path(), name, depth + 1));
            }
        } else if ft.is_file() {
            if let Ok(meta) = e.metadata() {
                w.files.push((name, e.path(), meta.len(), mtime_of(&meta)));
            }
        }
    }
    w
}

fn count_files(w: &WalkDir, out: &mut Vec<(PathBuf, u64, u64)>) {
    for (_, p, s, m) in &w.files {
        out.push((p.clone(), *s, *m));
    }
    for s in &w.subdirs {
        count_files(s, out);
    }
}

fn dir_hash(salt: &[u8], parent: &Hash, name: &str) -> Hash {
    let mut d = salt.to_vec();
    d.extend(parent);
    d.extend(name.as_bytes());
    sha1(&d)
}

/// Builds our tree from the walked folders and the hash cache.
fn build_tree(walked: &[(SharedDir, WalkDir)], cache: &mut HashCache, salt: &[u8]) -> LocalTree {
    let mut t = LocalTree::default();
    t.dirs.push(LocalDir {
        hash: NULL_HASH,
        name: String::new(),
        path: PathBuf::new(),
        mtime: 0,
        recurs: 0,
        parent: 0,
        subdirs: vec![],
        files: vec![],
        flags: 0,
    });
    t.by_hash.insert(NULL_HASH, 0);
    let mut seen_dirs = HashSet::new();
    for (shared, w) in walked {
        // top level: the hash uses the real path (dir_name at level 1 is the path in RetroShare)
        let hash = dir_hash(salt, &NULL_HASH, &shared.path);
        let idx = add_dir(&mut t, cache, salt, w, hash, shared.virtual_name.clone(), 0, shared.flags, &mut seen_dirs);
        t.dirs[0].subdirs.push(idx);
    }
    // root: its "content" also includes the folder flags
    let mut digest = vec![];
    let mut recurs = 0;
    for i in t.dirs[0].subdirs.clone() {
        let d = &t.dirs[i];
        digest.extend(d.hash);
        digest.extend(d.recurs.to_be_bytes());
        digest.extend(d.flags.to_be_bytes());
        digest.extend(d.name.as_bytes());
        recurs = recurs.max(d.recurs);
    }
    let root_recurs = settle_recurs(cache, &NULL_HASH, &digest, recurs);
    t.dirs[0].recurs = root_recurs;
    t.dirs[0].mtime = root_recurs;
    seen_dirs.insert(hash_hex(&NULL_HASH));
    cache.dirs.retain(|k, _| seen_dirs.contains(k));
    t
}

/// The recursive modification time of a folder: kept while its content (digest) is the
/// same, a new one (now) when it changed, so friends notice.
fn settle_recurs(cache: &mut HashCache, hash: &Hash, content: &[u8], below: u32) -> u32 {
    let digest = hash_hex(&sha1(content));
    let key = hash_hex(hash);
    let recurs = match cache.dirs.get(&key) {
        Some((d, r)) if *d == digest => (*r).max(below),
        Some((_, r)) => (now() as u32).max(*r + 1).max(below),
        None => (now() as u32).max(below),
    };
    cache.dirs.insert(key, (digest, recurs));
    recurs
}

#[allow(clippy::too_many_arguments)]
fn add_dir(
    t: &mut LocalTree,
    cache: &mut HashCache,
    salt: &[u8],
    w: &WalkDir,
    hash: Hash,
    name: String,
    parent: usize,
    flags: u32,
    seen: &mut HashSet<String>,
) -> usize {
    let idx = t.dirs.len();
    t.dirs.push(LocalDir {
        hash,
        name,
        path: w.path.clone(),
        mtime: w.mtime,
        recurs: 0,
        parent,
        subdirs: vec![],
        files: vec![],
        flags,
    });
    t.by_hash.insert(hash, idx);
    seen.insert(hash_hex(&hash));
    let mut subdirs = vec![];
    for s in &w.subdirs {
        let h = dir_hash(salt, &hash, &s.name);
        subdirs.push(add_dir(t, cache, salt, s, h, s.name.clone(), idx, flags, seen));
    }
    let mut files = vec![];
    for (name, path, size, mtime) in &w.files {
        let key = path.display().to_string();
        let Some(c) = cache.files.get(&key) else { continue };
        if c.size != *size || c.mtime != *mtime {
            continue; // changed, not hashed again yet
        }
        let Some(h) = parse_hash(&c.hash) else { continue };
        files.push(LocalFile { name: name.clone(), path: path.clone(), size: *size, hash: h, mtime: *mtime as u32 });
        t.total_files += 1;
        t.total_size += size;
        t.files.entry(h).or_insert_with(|| (path.clone(), *size, name.clone(), flags));
    }
    // content digest: name, files and the sub folders' times
    let mut digest = vec![];
    digest.extend(t.dirs[idx].name.as_bytes());
    digest.extend(w.mtime.to_be_bytes());
    let mut below = w.mtime;
    for &s in &subdirs {
        digest.extend(t.dirs[s].hash);
        digest.extend(t.dirs[s].recurs.to_be_bytes());
        below = below.max(t.dirs[s].recurs);
    }
    for f in &files {
        digest.extend(f.name.as_bytes());
        digest.extend(f.size.to_be_bytes());
        digest.extend(f.hash);
        digest.extend(f.mtime.to_be_bytes());
        below = below.max(f.mtime);
    }
    let recurs = settle_recurs(cache, &hash, &digest, below);
    let d = &mut t.dirs[idx];
    d.subdirs = subdirs;
    d.files = files;
    d.recurs = recurs;
    idx
}

fn load_cache(dir: &Path) -> HashCache {
    fs::read(dir.join(HASH_CACHE_FILE)).ok().and_then(|d| serde_json::from_slice(&d).ok()).unwrap_or_default()
}

fn save_cache(dir: &Path, cache: &HashCache) {
    if let Ok(d) = serde_json::to_vec(cache) {
        if let Err(e) = fs::write(dir.join(HASH_CACHE_FILE), d) {
            warn!("[files] can't save {HASH_CACHE_FILE}: {e}");
        }
    }
}

/// Scans the shared folders now and every RESCAN_SECS, hashing new and changed files.
async fn scanner() {
    let Some(config_dir) = files().map(|f| f.config_dir.clone()) else { return };
    let mut cache = load_cache(&config_dir);
    loop {
        let (shared, salt) = match files() {
            Some(mut f) => {
                f.scanning = true;
                (f.config.shared.clone(), hex::decode(&f.config.salt).unwrap_or_default())
            }
            None => return,
        };
        let walked: Vec<(SharedDir, WalkDir)> = {
            let shared = shared.clone();
            tokio::task::spawn_blocking(move || {
                shared
                    .into_iter()
                    .filter(|s| Path::new(&s.path).is_dir())
                    .map(|s| {
                        let w = walk(Path::new(&s.path), s.virtual_name.clone(), 0);
                        (s, w)
                    })
                    .collect()
            })
            .await
            .unwrap_or_default()
        };

        // publish what we know, then hash what is new
        let tree = build_tree(&walked, &mut cache, &salt);
        if let Some(mut f) = files() {
            f.local = tree;
        }
        let mut all = vec![];
        for (_, w) in &walked {
            count_files(w, &mut all);
        }
        let todo: Vec<(PathBuf, u64, u64)> = all
            .into_iter()
            .filter(|(p, s, m)| {
                cache.files.get(&p.display().to_string()).map(|c| c.size != *s || c.mtime != *m).unwrap_or(true)
            })
            .collect();
        if !todo.is_empty() {
            info!("[files] hashing {} files", todo.len());
            let total = todo.len();
            let mut last_publish = Instant::now();
            for (n, (path, size, mtime)) in todo.into_iter().enumerate() {
                if let Some(mut f) = files() {
                    f.hashing = Some(HashingStatus {
                        file: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                        done: n,
                        total,
                    });
                }
                let p = path.clone();
                let res = tokio::task::spawn_blocking(move || hash_file(&p, |_| {})).await;
                match res {
                    Ok(Ok(h)) => {
                        cache.files.insert(path.display().to_string(), CacheEntry { size, mtime, hash: hash_hex(&h) });
                    }
                    Ok(Err(e)) => warn!("[files] can't hash {}: {e}", path.display()),
                    Err(_) => {}
                }
                // friends see newly hashed files every 30 s
                if last_publish.elapsed().as_secs() >= 30 {
                    last_publish = Instant::now();
                    let tree = build_tree(&walked, &mut cache, &salt);
                    if let Some(mut f) = files() {
                        f.local = tree;
                    }
                    save_cache(&config_dir, &cache);
                }
            }
            let tree = build_tree(&walked, &mut cache, &salt);
            if let Some(mut f) = files() {
                f.local = tree;
            }
        }
        // forget files that are not shared anymore
        let mut present = HashSet::new();
        for (_, w) in &walked {
            let mut all = vec![];
            count_files(w, &mut all);
            present.extend(all.into_iter().map(|(p, _, _)| p.display().to_string()));
        }
        cache.files.retain(|k, _| present.contains(k));
        save_cache(&config_dir, &cache);
        if let Some(mut f) = files() {
            f.hashing = None;
            f.scanning = false;
            info!("[files] shared: {} files, {} bytes", f.local.total_files, f.local.total_size);
        }

        tokio::select! {
            _ = RESCAN.get_or_init(Notify::new).notified() => {}
            _ = tokio::time::sleep(std::time::Duration::from_secs(RESCAN_SECS)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_125_round_trip() {
        for s in [0u32, 1, 191, 192, 300, 8383, 8384, 100_000] {
            let mut out = vec![0x40];
            fl_size(&mut out, s);
            out.extend(vec![0; s as usize]);
            let mut r = FlReader::new(&out);
            assert_eq!(r.field(0x40).map(|d| d.len()), Some(s as usize), "size {s}");
        }
    }

    #[test]
    fn dir_round_trip() {
        let mut t = LocalTree::default();
        t.dirs.push(LocalDir {
            hash: NULL_HASH,
            name: String::new(),
            path: PathBuf::new(),
            mtime: 5,
            recurs: 7,
            parent: 0,
            subdirs: vec![1],
            files: vec![],
            flags: 0,
        });
        t.dirs.push(LocalDir {
            hash: [1; 20],
            name: "Music".into(),
            path: PathBuf::new(),
            mtime: 5,
            recurs: 7,
            parent: 0,
            subdirs: vec![],
            files: vec![LocalFile { name: "a.mp3".into(), path: PathBuf::new(), size: 1234, hash: [9; 20], mtime: 3 }],
            flags: DIR_FLAGS_BROWSABLE,
        });
        let mut r = RemoteTree::new();
        assert!(r.update_dir(&NULL_HASH, &t.serialise_dir(0).unwrap()));
        assert_eq!(r.dirs[&NULL_HASH].subdirs, vec![[1; 20]]);
        assert!(r.update_dir(&[1; 20], &t.serialise_dir(1).unwrap()));
        let d = &r.dirs[&[1; 20]];
        assert_eq!(d.name, "Music");
        assert_eq!(d.files[0].name, "a.mp3");
        assert_eq!(d.files[0].size, 1234);
        assert_eq!(d.recurs, 7);
    }

    #[test]
    fn ranges_merge() {
        let mut r = vec![];
        add_range(&mut r, 10, 20);
        add_range(&mut r, 0, 10);
        add_range(&mut r, 30, 40);
        assert_eq!(r, vec![(0, 20), (30, 40)]);
        add_range(&mut r, 15, 35);
        assert_eq!(r, vec![(0, 40)]);
    }
}
