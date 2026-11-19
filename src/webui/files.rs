//! rsFiles JSON API, like libretroshare's `retroshare/rsfiles.h` (RetroShare's JSON API
//! serves it as /rsFiles/...): shared folders, download folder, FileRequest / FileCancel /
//! FileControl. Browsing (own and friends' folders), the transfer list, searching friends'
//! lists and a folder chooser for the web UI are rustyshare additions in the same scope.

use std::{path::PathBuf, sync::Arc};

use actix_web::{post, web, Responder, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    files::{self, hash_hex, parse_hash, Hash, SharedDir, NULL_HASH},
    model::DataCore,
};

// FileControl flags (retroshare/rstypes.h)
const RS_FILE_CTRL_PAUSE: u32 = 0x0000_0100;
const RS_FILE_CTRL_START: u32 = 0x0000_0200;
const RS_FILE_CTRL_FORCE_CHECK: u32 = 0x0000_0400;

fn ok(v: bool) -> web::Json<Value> {
    web::Json(json!({ "retval": v }))
}

fn shared_json(d: &SharedDir) -> Value {
    json!({ "filename": d.path, "virtualname": d.virtual_name, "shareflags": d.flags, "parent_groups": [] })
}

#[post("/getSharedDirectories")]
pub async fn get_shared_directories() -> Result<impl Responder> {
    let dirs: Vec<Value> = files::files().map(|f| f.config.shared.iter().map(shared_json).collect()).unwrap_or_default();
    Ok(web::Json(json!({ "retval": true, "dirs": dirs })))
}

#[derive(Deserialize)]
pub struct SharedDirIn {
    filename: String,
    #[serde(default)]
    virtualname: String,
    #[serde(default)]
    shareflags: u32,
}

#[derive(Deserialize)]
pub struct DirParam {
    dir: SharedDirIn,
}

/// a unique virtual name: the folder name, "name-2", ...
fn virtual_name(shared: &[SharedDir], wanted: &str, path: &str) -> String {
    let base = if wanted.trim().is_empty() {
        PathBuf::from(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "share".to_owned())
    } else {
        wanted.trim().to_owned()
    };
    let mut name = base.clone();
    let mut n = 2;
    while shared.iter().any(|s| s.virtual_name == name && s.path != path) {
        name = format!("{base}-{n}");
        n += 1;
    }
    name
}

#[post("/addSharedDirectory")]
pub async fn add_shared_directory(params: web::Json<DirParam>) -> Result<impl Responder> {
    // no trailing separator, except for a drive or the root ("C:\\", "/")
    let raw = params.dir.filename.trim();
    let trimmed = raw.trim_end_matches(['/', '\\']);
    let path = if trimmed.is_empty() || trimmed.ends_with(':') { raw.to_owned() } else { trimmed.to_owned() };
    if path.is_empty() || !PathBuf::from(&path).is_dir() {
        return Ok(web::Json(json!({ "retval": false, "errorMessage": "this folder doesn't exist" })));
    }
    let Some(mut f) = files::files() else { return Ok(ok(false)) };
    if f.config.shared.iter().any(|s| s.path == path) {
        return Ok(web::Json(json!({ "retval": false, "errorMessage": "this folder is already shared" })));
    }
    let name = virtual_name(&f.config.shared, &params.dir.virtualname, &path);
    f.config.shared.push(SharedDir { path, virtual_name: name, flags: params.dir.shareflags });
    f.save_config();
    files::rescan();
    Ok(ok(true))
}

#[post("/updateShareFlags")]
pub async fn update_share_flags(params: web::Json<DirParam>) -> Result<impl Responder> {
    let Some(mut f) = files::files() else { return Ok(ok(false)) };
    let wanted = params.dir.virtualname.clone();
    let path = params.dir.filename.clone();
    let name = virtual_name(&f.config.shared, &wanted, &path);
    let Some(d) = f.config.shared.iter_mut().find(|s| s.path == path) else { return Ok(ok(false)) };
    d.flags = params.dir.shareflags;
    if !wanted.trim().is_empty() {
        d.virtual_name = name;
    }
    f.save_config();
    files::rescan();
    Ok(ok(true))
}

#[derive(Deserialize)]
pub struct RemoveParam {
    dir: String,
}

#[post("/removeSharedDirectory")]
pub async fn remove_shared_directory(params: web::Json<RemoveParam>) -> Result<impl Responder> {
    let Some(mut f) = files::files() else { return Ok(ok(false)) };
    let before = f.config.shared.len();
    f.config.shared.retain(|s| s.path != params.dir);
    let removed = f.config.shared.len() != before;
    if removed {
        f.save_config();
        files::rescan();
    }
    Ok(ok(removed))
}

#[post("/getDownloadDirectory")]
pub async fn get_download_directory() -> Result<impl Responder> {
    let d = files::files().map(|f| f.config.download_dir.clone()).unwrap_or_default();
    Ok(web::Json(json!({ "retval": d })))
}

#[post("/getPartialsDirectory")]
pub async fn get_partials_directory() -> Result<impl Responder> {
    let d = files::files().map(|f| f.config.partials_dir.clone()).unwrap_or_default();
    Ok(web::Json(json!({ "retval": d })))
}

#[derive(Deserialize)]
pub struct PathParam {
    path: String,
}

#[post("/setDownloadDirectory")]
pub async fn set_download_directory(params: web::Json<PathParam>) -> Result<impl Responder> {
    let p = params.path.trim();
    if p.is_empty() || std::fs::create_dir_all(p).is_err() {
        return Ok(ok(false));
    }
    let Some(mut f) = files::files() else { return Ok(ok(false)) };
    f.config.download_dir = p.to_owned();
    f.save_config();
    Ok(ok(true))
}

#[post("/setPartialsDirectory")]
pub async fn set_partials_directory(params: web::Json<PathParam>) -> Result<impl Responder> {
    let p = params.path.trim();
    if p.is_empty() || std::fs::create_dir_all(p).is_err() {
        return Ok(ok(false));
    }
    let Some(mut f) = files::files() else { return Ok(ok(false)) };
    // unfinished downloads move along
    let old = PathBuf::from(&f.config.partials_dir);
    for d in f.downloads.values().filter(|d| d.state != files::DL_COMPLETE) {
        let from = old.join(&d.hash);
        if from.exists() {
            let to = PathBuf::from(p).join(&d.hash);
            if std::fs::rename(&from, &to).is_err() {
                let _ = std::fs::copy(&from, &to).and_then(|_| std::fs::remove_file(&from));
            }
        }
    }
    f.config.partials_dir = p.to_owned();
    f.save_config();
    Ok(ok(true))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileRequestIn {
    file_name: String,
    hash: String,
    size: u64,
    #[serde(default)]
    dest_path: String,
    #[serde(default)]
    src_ids: Vec<String>,
}

/// rsFiles::FileRequest(fileName, hash, size, destPath, flags, srcIds)
#[post("/FileRequest")]
pub async fn file_request(params: web::Json<FileRequestIn>) -> Result<impl Responder> {
    if parse_hash(&params.hash).is_none() {
        return Ok(ok(false));
    }
    let Some(mut f) = files::files() else { return Ok(ok(false)) };
    let sources: Vec<String> = params.src_ids.iter().map(|s| s.to_lowercase()).collect();
    Ok(ok(f.add_download(&params.hash, &params.file_name, params.size, sources, &params.dest_path)))
}

#[derive(Deserialize)]
pub struct HashParam {
    hash: String,
}

/// rsFiles::FileCancel(): stops the download and deletes the partial file
#[post("/FileCancel")]
pub async fn file_cancel(params: web::Json<HashParam>) -> Result<impl Responder> {
    let Some(mut f) = files::files() else { return Ok(ok(false)) };
    let partials = f.config.partials_dir.clone();
    let Some(d) = f.downloads.remove(&params.hash.to_lowercase()) else { return Ok(ok(false)) };
    if d.state != files::DL_COMPLETE {
        let _ = std::fs::remove_file(d.partial_path(&partials));
    }
    f.save_downloads(true);
    Ok(ok(true))
}

#[derive(Deserialize)]
pub struct ControlParam {
    hash: String,
    flags: u32,
}

/// rsFiles::FileControl(): pause, start, check again
#[post("/FileControl")]
pub async fn file_control(params: web::Json<ControlParam>) -> Result<impl Responder> {
    let Some(mut f) = files::files() else { return Ok(ok(false)) };
    let Some(d) = f.downloads.get_mut(&params.hash.to_lowercase()) else { return Ok(ok(false)) };
    if d.state == files::DL_COMPLETE {
        return Ok(ok(false));
    }
    if params.flags & RS_FILE_CTRL_PAUSE != 0 {
        d.state = files::DL_PAUSED;
        d.runtime.in_flight.clear();
    } else if params.flags & (RS_FILE_CTRL_START | RS_FILE_CTRL_FORCE_CHECK) != 0 {
        d.state = files::DL_DOWNLOADING;
        d.error.clear();
        if params.flags & RS_FILE_CTRL_FORCE_CHECK != 0 && d.all_done() {
            d.state = files::DL_DOWNLOADING; // the transfer service checks it again
        }
    }
    f.save_downloads(true);
    files::transfers_changed();
    Ok(ok(true))
}

/// rsFiles::FileClearCompleted()
#[post("/FileClearCompleted")]
pub async fn file_clear_completed() -> Result<impl Responder> {
    let Some(mut f) = files::files() else { return Ok(ok(false)) };
    f.downloads.retain(|_, d| d.state != files::DL_COMPLETE);
    f.save_downloads(true);
    Ok(ok(true))
}

// --- rustyshare additions for the web UI ----------------------------------------------------

/// sharing state: hashing progress, totals, folders
#[post("/rustyshareStatus")]
pub async fn status() -> Result<impl Responder> {
    let Some(f) = files::files() else { return Ok(ok(false)) };
    Ok(web::Json(json!({
        "retval": true,
        "hashing": f.hashing,
        "scanning": f.scanning,
        "total_files": f.local.total_files,
        "total_size": f.local.total_size,
        "download_dir": f.config.download_dir,
        "partials_dir": f.config.partials_dir,
    })))
}

/// downloads and uploads
#[post("/rustyshareTransfers")]
pub async fn transfers(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    let names: std::collections::HashMap<String, String> = state
        .get_locations()
        .iter()
        .map(|l| (l.get_location_id().to_string(), l.get_name().to_owned()))
        .collect();
    let Some(f) = files::files() else { return Ok(ok(false)) };
    let downloads: Vec<Value> = f
        .downloads
        .values()
        .map(|d| {
            let done = if d.state == files::DL_COMPLETE { d.size } else { d.done_bytes() };
            json!({
                "hash": d.hash, "name": d.name, "size": d.size, "done": done,
                "rate": d.rate(), "state": d.state, "added": d.added, "completed": d.completed,
                "path": d.path, "error": d.error,
                "sources": d.sources.iter().map(|s| json!({ "id": s, "name": names.get(s).cloned().unwrap_or_default() })).collect::<Vec<_>>(),
                "chunks": d.chunks(), "chunks_done": (0..d.chunks()).filter(|c| d.is_done(*c)).count(),
            })
        })
        .collect();
    let uploads: Vec<Value> = f
        .uploads
        .values()
        .map(|u| {
            json!({
                "hash": u.hash, "name": u.name, "size": u.size, "sent": u.sent, "rate": u.rate(), "last": u.last,
                "peer": u.peer, "peer_name": names.get(&u.peer).cloned().unwrap_or_default(),
            })
        })
        .collect();
    Ok(web::Json(json!({ "retval": true, "downloads": downloads, "uploads": uploads })))
}

#[derive(Deserialize)]
pub struct DirIn {
    #[serde(default)]
    peer: String,
    #[serde(default)]
    hash: String,
}

/// one of our folders as friends see it (empty hash: the root)
#[post("/rustyshareOwnDir")]
pub async fn own_dir(params: web::Json<DirIn>) -> Result<impl Responder> {
    let hash = parse_hash(&params.hash).unwrap_or(NULL_HASH);
    let Some(f) = files::files() else { return Ok(ok(false)) };
    let t = &f.local;
    let Some(&i) = t.by_hash.get(&hash) else { return Ok(ok(false)) };
    let d = &t.dirs[i];
    let mut path = vec![];
    let mut p = i;
    while p != 0 {
        path.push(json!({ "hash": hash_hex(&t.dirs[p].hash), "name": t.dirs[p].name }));
        p = t.dirs[p].parent;
    }
    path.reverse();
    let subdirs: Vec<Value> = d
        .subdirs
        .iter()
        .map(|&s| {
            let sd = &t.dirs[s];
            json!({ "hash": hash_hex(&sd.hash), "name": sd.name, "count": sd.subdirs.len() + sd.files.len(),
                    "flags": sd.flags, "path": sd.path.display().to_string() })
        })
        .collect();
    let files_out: Vec<Value> = d
        .files
        .iter()
        .map(|fl| json!({ "name": fl.name, "size": fl.size, "hash": hash_hex(&fl.hash), "mtime": fl.mtime }))
        .collect();
    Ok(web::Json(json!({ "retval": true, "hash": hash_hex(&hash), "name": d.name, "path": path,
                          "subdirs": subdirs, "files": files_out, "loaded": true })))
}

/// a friend's folder (empty hash: the root); asks for it again when it is old
#[post("/rustyshareFriendDir")]
pub async fn friend_dir(params: web::Json<DirIn>) -> Result<impl Responder> {
    let peer = params.peer.to_lowercase();
    let hash = parse_hash(&params.hash).unwrap_or(NULL_HASH);
    crate::services::file_lists::refresh_dir(&peer, &hash);
    let Some(f) = files::files() else { return Ok(ok(false)) };
    let Some(t) = f.remote.get(&peer) else {
        return Ok(web::Json(json!({ "retval": true, "hash": hash_hex(&hash), "name": "", "path": [], "subdirs": [], "files": [], "loaded": false, "online": false })));
    };
    let Some(d) = t.dirs.get(&hash) else { return Ok(ok(false)) };
    let mut path = vec![];
    let mut cur: Option<Hash> = (hash != NULL_HASH).then_some(hash);
    while let Some(h) = cur {
        let Some(x) = t.dirs.get(&h) else { break };
        path.push(json!({ "hash": hash_hex(&h), "name": x.name }));
        cur = x.parent.filter(|p| *p != NULL_HASH);
    }
    path.reverse();
    let subdirs: Vec<Value> = d
        .subdirs
        .iter()
        .filter_map(|h| t.dirs.get(h).map(|sd| (h, sd)))
        .map(|(h, sd)| json!({ "hash": hash_hex(h), "name": sd.name, "loaded": sd.updated != 0,
                               "count": sd.subdirs.len() + sd.files.len() }))
        .collect();
    let (count, size) = t.file_count();
    Ok(web::Json(json!({ "retval": true, "hash": hash_hex(&hash), "name": d.name, "path": path,
                          "subdirs": subdirs, "files": d.files, "loaded": d.updated != 0, "online": true,
                          "total_files": count, "total_size": size })))
}

/// friends whose lists we have
#[post("/rustyshareFriendLists")]
pub async fn friend_lists(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    let names: std::collections::HashMap<String, (String, String)> = state
        .get_locations()
        .iter()
        .map(|l| (l.get_location_id().to_string(), (l.get_name().to_owned(), l.get_person().get_name().to_owned())))
        .collect();
    let Some(f) = files::files() else { return Ok(ok(false)) };
    let mut out: Vec<Value> = f
        .remote
        .iter()
        .map(|(peer, t)| {
            let (count, size) = t.file_count();
            let (loc, person) = names.get(peer).cloned().unwrap_or_default();
            json!({ "peer": peer, "location": loc, "name": person, "files": count, "size": size,
                    "loaded": t.dirs.get(&NULL_HASH).map(|d| d.updated != 0).unwrap_or(false),
                    "pending": t.pending.len() })
        })
        .collect();
    out.sort_by_key(|v| v["name"].as_str().unwrap_or_default().to_lowercase());
    Ok(web::Json(json!({ "retval": true, "friends": out })))
}

#[derive(Deserialize)]
pub struct SearchIn {
    q: String,
}

/// searches friends' lists (names containing all words)
#[post("/rustyshareSearch")]
pub async fn search(params: web::Json<SearchIn>) -> Result<impl Responder> {
    let words: Vec<String> = params.q.to_lowercase().split_whitespace().map(|w| w.to_owned()).collect();
    if words.is_empty() {
        return Ok(web::Json(json!({ "retval": true, "results": [] })));
    }
    let Some(f) = files::files() else { return Ok(ok(false)) };
    let mut results = vec![];
    'outer: for (peer, t) in &f.remote {
        for (dh, d) in &t.dirs {
            for fl in &d.files {
                let n = fl.name.to_lowercase();
                if words.iter().all(|w| n.contains(w.as_str())) {
                    results.push(json!({ "peer": peer, "dir": hash_hex(dh), "dir_name": d.name,
                                         "name": fl.name, "size": fl.size, "hash": hash_hex(&fl.hash) }));
                    if results.len() >= 500 {
                        break 'outer;
                    }
                }
            }
        }
    }
    Ok(web::Json(json!({ "retval": true, "results": results })))
}

/// downloads everything below a friend's folder (known so far), keeping the folders
#[post("/rustyshareDownloadDir")]
pub async fn download_dir(params: web::Json<DirIn>) -> Result<impl Responder> {
    let peer = params.peer.to_lowercase();
    let Some(hash) = parse_hash(&params.hash) else { return Ok(ok(false)) };
    let Some(mut f) = files::files() else { return Ok(ok(false)) };
    let mut todo = vec![];
    if let Some(t) = f.remote.get(&peer) {
        let mut stack = vec![(hash, t.dirs.get(&hash).map(|d| files::sanitize_name(&d.name)).unwrap_or_default())];
        while let Some((h, rel)) = stack.pop() {
            let Some(d) = t.dirs.get(&h) else { continue };
            for fl in &d.files {
                todo.push((hash_hex(&fl.hash), fl.name.clone(), fl.size, rel.clone()));
            }
            for s in &d.subdirs {
                let name = t.dirs.get(s).map(|x| files::sanitize_name(&x.name)).unwrap_or_default();
                stack.push((*s, format!("{rel}/{name}")));
            }
        }
    }
    let n = todo.len();
    for (h, name, size, rel) in todo {
        f.add_download(&h, &name, size, vec![peer.clone()], &rel);
    }
    Ok(web::Json(json!({ "retval": n > 0, "count": n })))
}

#[derive(Deserialize)]
pub struct BrowseIn {
    #[serde(default)]
    path: String,
}

/// folder chooser: the sub folders of a folder on this computer (empty: home and drives)
#[post("/rustyshareBrowseLocal")]
pub async fn browse_local(params: web::Json<BrowseIn>) -> Result<impl Responder> {
    let p = params.path.trim();
    if p.is_empty() {
        let mut roots = vec![];
        if let Some(h) = dirs::home_dir() {
            roots.push(h.display().to_string());
        }
        for d in [dirs::download_dir(), dirs::document_dir(), dirs::audio_dir(), dirs::video_dir(), dirs::picture_dir()].into_iter().flatten() {
            roots.push(d.display().to_string());
        }
        if cfg!(windows) {
            for letter in b'A'..=b'Z' {
                let d = format!("{}:\\", letter as char);
                if PathBuf::from(&d).is_dir() {
                    roots.push(d);
                }
            }
        } else {
            roots.push("/".to_owned());
        }
        return Ok(web::Json(json!({ "retval": true, "path": "", "parent": null, "dirs": roots, "roots": true })));
    }
    let path = PathBuf::from(p);
    let mut dirs: Vec<String> = match std::fs::read_dir(&path) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .collect(),
        Err(e) => return Ok(web::Json(json!({ "retval": false, "errorMessage": e.to_string() }))),
    };
    dirs.sort_by_key(|d| d.to_lowercase());
    let parent = path.parent().map(|p| p.display().to_string());
    Ok(web::Json(json!({ "retval": true, "path": path.display().to_string(), "parent": parent,
                          "dirs": dirs.into_iter().map(|d| path.join(d).display().to_string()).collect::<Vec<_>>(),
                          "roots": false })))
}

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsFiles")
        .service(get_shared_directories)
        .service(add_shared_directory)
        .service(update_share_flags)
        .service(remove_shared_directory)
        .service(get_download_directory)
        .service(get_partials_directory)
        .service(set_download_directory)
        .service(set_partials_directory)
        .service(file_request)
        .service(file_cancel)
        .service(file_control)
        .service(file_clear_completed)
        .service(status)
        .service(transfers)
        .service(own_dir)
        .service(friend_dir)
        .service(friend_lists)
        .service(search)
        .service(download_dir)
        .service(browse_local)
}
