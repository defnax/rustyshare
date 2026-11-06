//! rsGxsChannels JSON API, like libretroshare's `retroshare/rsgxschannels.h`:
//! channel list, subscribe, posts with thumbnails and file lists, comments and votes,
//! creating channels, posts, comments and votes.
//!
//! Item formats (libretroshare rsitems/rsgxschannelitems.h, rsgxscommentitems.h):
//! - group  `RsGxsChannelGroupItem` (0x02): description (TLV 0x00b3), image (TLV 0x1060)
//! - post   `RsGxsChannelPostItem`  (0x03): text (TLV 0x0057, HTML), files (TLV 0x1001),
//!   thumbnail (TLV 0x1060); root posts are signed with the channel's publish key
//! - comment `RsGxsCommentItem` (0xf1): text (string TLV type 1); author signed
//! - vote   `RsGxsVoteItem` (0xf2): u32 vote type (1 down, 2 up); author signed

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use actix_web::{post, web, Responder, Result};
use retroshare_compat::{
    basics::{GxsGroupId, GxsId},
    gxs::sqlite::{database::StoredMsg, types::SubscribeFlags},
    tlv::tlv_keys::{KeySignType, TlvKeyFlags},
    webui::identity::GxsGroupMeta,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{model::DataCore, webui::RetVal};

const SUBTYPE_POST: u8 = 0x03;
const SUBTYPE_COMMENT: u8 = 0xf1;
const SUBTYPE_VOTE: u8 = 0xf2;
/// RsGxsVoteType
const VOTE_DOWN: u32 = 1;
const VOTE_UP: u32 = 2;
/// biggest thumbnail / channel picture accepted from the web page (RetroShare scales
/// them down to a few hundred pixels anyway)
const MAX_PICTURE: usize = 512 * 1024;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn parse_group_id(id: &str) -> Option<GxsGroupId> {
    match hex::decode(id.trim()) {
        Ok(bytes) if bytes.len() == 16 => Some(GxsGroupId::from(bytes)),
        _ => None,
    }
}

fn parse_gxs_id(id: &str) -> Option<GxsId> {
    match hex::decode(id.trim()) {
        Ok(b) if b.len() == 16 => Some(b.into()),
        _ => None,
    }
}

fn to20(h: &str) -> Option<[u8; 20]> {
    hex::decode(h.trim()).ok()?.try_into().ok()
}

// --- item parsing --------------------------------------------------------------

/// The TLVs of an item body (after the 8 byte item header): (type, value).
fn tlvs(data: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = vec![];
    let mut pos = 8;
    while pos + 6 <= data.len() {
        let ty = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let len = u32::from_be_bytes([data[pos + 2], data[pos + 3], data[pos + 4], data[pos + 5]]) as usize;
        if len < 6 || pos + len > data.len() {
            break;
        }
        out.push((ty, &data[pos + 6..pos + len]));
        pos += len;
    }
    out
}

/// The picture inside a `RsTlvImage` value (u32 type, then TLV_TYPE_BIN_IMAGE).
fn image_bytes(value: &[u8]) -> &[u8] {
    if value.len() < 10 {
        return &[];
    }
    let len = u32::from_be_bytes([value[6], value[7], value[8], value[9]]) as usize;
    if len < 6 || 4 + len > value.len() {
        return &[];
    }
    &value[10..4 + len]
}

/// A picture as data URL for the web page (type guessed from the first bytes).
fn data_url(picture: &[u8]) -> String {
    if picture.is_empty() {
        return String::new();
    }
    let mime = match picture {
        [0x89, b'P', b'N', b'G', ..] => "image/png",
        [b'G', b'I', b'F', ..] => "image/gif",
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => "image/webp",
        _ => "image/jpeg",
    };
    format!("data:{mime};base64,{}", base64::encode(picture))
}

/// A data URL (or plain base64) from the web page back to bytes.
fn picture_from_page(text: &str) -> std::result::Result<Vec<u8>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(vec![]);
    }
    let b64 = text.split_once(',').map(|(_, b)| b).unwrap_or(text);
    let bytes = base64::decode(b64).map_err(|_| "the picture could not be read".to_string())?;
    if bytes.len() > MAX_PICTURE {
        return Err(format!("the picture is too big (at most {} kB)", MAX_PICTURE / 1024));
    }
    Ok(bytes)
}

#[derive(Serialize, Default, Clone)]
pub struct ChannelFile {
    name: String,
    size: u64,
    hash: String,
}

/// `RsTlvFileSet` value: file items (u64 size, 20 byte hash, optional name TLV, ...).
fn files(value: &[u8]) -> Vec<ChannelFile> {
    let mut out = vec![];
    let mut pos = 0;
    while pos + 6 <= value.len() {
        let ty = u16::from_be_bytes([value[pos], value[pos + 1]]);
        let len = u32::from_be_bytes([value[pos + 2], value[pos + 3], value[pos + 4], value[pos + 5]]) as usize;
        if len < 6 || pos + len > value.len() {
            break;
        }
        // TLV_TYPE_FILEITEM
        if ty == 0x1000 && len >= 6 + 8 + 20 {
            let item = &value[pos + 6..pos + len];
            let size = u64::from_be_bytes(item[0..8].try_into().unwrap_or_default());
            let hash = hex::encode(&item[8..28]);
            let mut name = String::new();
            let mut p = 28;
            while p + 6 <= item.len() {
                let t = u16::from_be_bytes([item[p], item[p + 1]]);
                let l = u32::from_be_bytes([item[p + 2], item[p + 3], item[p + 4], item[p + 5]]) as usize;
                if l < 6 || p + l > item.len() {
                    break;
                }
                if t == 0x0051 {
                    name = String::from_utf8_lossy(&item[p + 6..p + l]).into_owned();
                }
                p += l;
            }
            out.push(ChannelFile { name, size, hash });
        }
        pos += len;
    }
    out
}

fn sub_type(data: &[u8]) -> u8 {
    data.get(3).copied().unwrap_or(0)
}

// --- rsGxsChannels/getChannelsSummaries -----------------------------------------

#[derive(Serialize)]
pub struct ChannelsSummaries {
    retval: bool,
    channels: Vec<GxsGroupMeta>,
}
#[post("/getChannelsSummaries")]
pub async fn get_channels_summaries(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    let store = state.get_service_data().gxs_channels();
    // post count, last post and popularity from the friends' group statistics, like forums
    let stats: HashMap<String, (u32, u32, u32)> = store
        .group_stats()
        .await
        .into_iter()
        .map(|(id, posts, last, pop)| (id, (posts, last, pop)))
        .collect();
    let channels = store
        .get_group_meta_all()
        .await
        .into_iter()
        .map(|g| {
            let mut meta: GxsGroupMeta = g.into();
            if let Some((posts, last, pop)) = stats.get(&meta.group_id.to_string()) {
                meta.visible_msg_count = meta.visible_msg_count.max(*posts);
                meta.pop = meta.pop.max(*pop);
                if (*last as i64) > i64::from(meta.last_post.clone()) {
                    meta.last_post = (*last as i64).into();
                }
            }
            meta
        })
        .collect();
    Ok(web::Json(ChannelsSummaries { retval: true, channels }))
}

// --- rsGxsChannels/getChannelInfo (rustyshare): one channel with its picture ----

#[derive(Deserialize)]
pub struct ChannelIn {
    #[serde(rename = "channelId")]
    channel_id: String,
}
#[derive(Serialize, Default)]
pub struct ChannelInfo {
    id: String,
    name: String,
    description: String,
    /// data URL, empty when the channel has no picture
    image: String,
    created: i64,
    last_post: i64,
    subscribed: bool,
    own: bool,
    /// we can post (we have the publish key)
    publish: bool,
    received_from: String,
}
#[post("/getChannelInfo")]
pub async fn get_channel_info(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<ChannelIn>,
) -> Result<impl Responder> {
    let fail = || web::Json(json!({ "retval": false }));
    let Some(group_id) = parse_group_id(&params.channel_id) else { return Ok(fail()) };
    let Some(group) = state.get_service_data().gxs_channels().get_group_with_data(&group_id).await else {
        return Ok(fail());
    };
    let data = group.get_blobs().nxs_data;
    let mut info = ChannelInfo {
        id: group.group_id.to_string(),
        name: group.group_name.to_owned(),
        created: group.publish_ts,
        last_post: group.last_post,
        subscribed: group.subscribe_flags.contains(SubscribeFlags::SUBSCRIBED),
        own: group.subscribe_flags.contains(SubscribeFlags::ADMIN),
        publish: group
            .keys
            .private_keys
            .iter()
            .any(|k| k.key_flags.contains(TlvKeyFlags::DISTRIBUTE_PUBLISH)),
        received_from: if group.originator == Default::default() {
            String::new()
        } else {
            group.originator.to_string()
        },
        ..Default::default()
    };
    for (ty, value) in tlvs(&data) {
        match ty {
            0x00b3 => info.description = String::from_utf8_lossy(value).into_owned(),
            0x1060 => info.image = data_url(image_bytes(value)),
            _ => {}
        }
    }
    Ok(web::Json(json!({ "retval": true, "info": info })))
}

// --- rsGxsChannels/subscribeToChannel {channelId, subscribe} ---------------------

#[derive(Deserialize)]
pub struct SubscribeIn {
    #[serde(rename = "channelId")]
    channel_id: String,
    subscribe: bool,
}
#[post("/subscribeToChannel")]
pub async fn subscribe_to_channel(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SubscribeIn>,
) -> Result<impl Responder> {
    let ok = match parse_group_id(&params.channel_id) {
        Some(id) => state.get_service_data().gxs_channels().subscribe(&id, params.subscribe).await,
        None => false,
    };
    Ok(web::Json(RetVal { retval: ok }))
}

// --- rsGxsChannels/getChannelAllContent {channelId} ------------------------------
// The verified posts, comments and vote counts of a channel. Like
// RsGenExchange::validateMsg(): posts need the channel's publish signature, comments
// and votes the author's identity signature (author unknown: requested, the message
// waits; wrong signature: deleted). Banned authors are left out.

#[derive(Serialize)]
pub struct ChannelPost {
    id: String,
    orig_msg_id: String,
    title: String,
    /// HTML
    text: String,
    /// data URL
    thumbnail: String,
    files: Vec<ChannelFile>,
    published: i64,
    unread: bool,
    comments: usize,
}
#[derive(Serialize)]
pub struct ChannelComment {
    id: String,
    /// the post
    thread_id: String,
    /// the post, or the comment this one answers
    parent_id: String,
    author_id: String,
    author_name: String,
    text: String,
    published: i64,
    up: u32,
    down: u32,
    /// our vote: 0 none, 1 down, 2 up
    own_vote: u32,
}

/// When we first tried to check a message whose author identity is unknown.
fn waited_too_long(msg_id: &str) -> bool {
    use std::sync::{Mutex, OnceLock};
    static FIRST_TRY: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    const MAX_WAIT: i64 = 120;
    let now = now();
    let mut map = FIRST_TRY.get_or_init(Default::default).lock().expect("lock poisoned");
    let first = *map.entry(msg_id.to_owned()).or_insert(now);
    if now - first > MAX_WAIT {
        map.remove(msg_id);
        true
    } else {
        false
    }
}

enum Check {
    Ok,
    Wait,
    Bad,
}

#[post("/getChannelAllContent")]
pub async fn get_channel_all_content(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<ChannelIn>,
) -> Result<impl Responder> {
    let Some(group_id) = parse_group_id(&params.channel_id) else {
        return Ok(web::Json(json!({ "retval": false })));
    };
    let channels = state.get_service_data().gxs_channels();
    let ids = state.get_service_data().gxs_id();

    // the channel's public publish key, for the posts
    let publish_key = channels.get_group_meta(&group_id).await.and_then(|g| {
        g.keys
            .public_keys
            .into_iter()
            .find(|k| k.key_flags.contains(TlvKeyFlags::DISTRIBUTE_PUBLISH))
    });

    let msgs = channels.get_messages(&group_id).await;
    let mut status_updates = vec![];
    let mut pending = 0;
    let mut checked: Vec<StoredMsg> = vec![];

    for msg in msgs {
        let ty = sub_type(&msg.data);
        if !matches!(ty, SUBTYPE_POST | SUBTYPE_COMMENT | SUBTYPE_VOTE) {
            continue;
        }
        let check = if msg.status & 1 == 1 {
            Check::Ok
        } else if ty == SUBTYPE_POST && msg.parent_id.is_empty() {
            match &publish_key {
                Some(key) => {
                    match crate::gxs::create_id::verify_msg_signature(&msg.meta, &msg.data, key, KeySignType::IndexAuthenPublish) {
                        Ok(true) => Check::Ok,
                        Ok(false) => Check::Bad,
                        Err(err) => {
                            log::warn!("channel post {}: {err}", msg.msg_id);
                            Check::Bad
                        }
                    }
                }
                // channel without public publish key: can't be checked, don't show it
                None => Check::Wait,
            }
        } else {
            match parse_gxs_id(&msg.author_id) {
                None => Check::Bad, // comments and votes need an author
                Some(author) => match ids.get_pub_keys_by_id(&author).await {
                    Some(key) => match crate::gxs::create_id::verify_msg_author_signature(&msg.meta, &msg.data, &key) {
                        Ok(true) => Check::Ok,
                        Ok(false) | Err(_) => Check::Bad,
                    },
                    None if waited_too_long(&msg.msg_id) => Check::Bad,
                    None => Check::Wait,
                },
            }
        };
        match check {
            Check::Ok => {
                if msg.status & 1 != 1 {
                    status_updates.push((msg.msg_id.to_owned(), 1));
                }
                checked.push(msg);
            }
            Check::Wait => pending += 1,
            Check::Bad => {
                log::warn!("channel message {} has a wrong or missing signature, deleted", msg.msg_id);
                status_updates.push((msg.msg_id.to_owned(), -1));
            }
        }
    }
    channels.set_message_status(status_updates).await;

    // votes: per voted message (comment or post) and author, the newest one counts
    let own_ids: HashSet<String> = if checked.iter().any(|m| sub_type(&m.data) == SUBTYPE_VOTE) {
        own_identity_ids(&state).await
    } else {
        HashSet::new()
    };
    let mut votes: HashMap<(String, String), (i64, u32)> = HashMap::new();
    for m in checked.iter().filter(|m| sub_type(&m.data) == SUBTYPE_VOTE) {
        let Some(v) = m.data.get(8..12) else { continue };
        let vote = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
        let key = (m.parent_id.to_owned(), m.author_id.to_owned());
        let e = votes.entry(key).or_insert((0, 0));
        if m.publish_ts >= e.0 {
            *e = (m.publish_ts, vote);
        }
    }
    let mut score: HashMap<String, (u32, u32, u32)> = HashMap::new();
    for ((target, author), (_, vote)) in &votes {
        let s = score.entry(target.to_owned()).or_default();
        match *vote {
            VOTE_UP => s.0 += 1,
            VOTE_DOWN => s.1 += 1,
            _ => {}
        }
        if own_ids.contains(author) {
            s.2 = *vote;
        }
    }

    let mut names: HashMap<String, String> = HashMap::new();
    let mut comments = vec![];
    let mut comment_count: HashMap<String, usize> = HashMap::new();
    for m in checked.iter().filter(|m| sub_type(&m.data) == SUBTYPE_COMMENT) {
        if state.reputation_is_banned(&m.author_id) {
            continue;
        }
        let author_name = match names.get(&m.author_id) {
            Some(n) => n.to_owned(),
            None => {
                let n = match parse_gxs_id(&m.author_id) {
                    Some(a) => ids.get_group_meta(&a.into()).await.map(|g| g.group_name).unwrap_or_default(),
                    None => String::new(),
                };
                names.insert(m.author_id.to_owned(), n.to_owned());
                n
            }
        };
        let text = tlvs(&m.data)
            .into_iter()
            .find(|(t, _)| *t == 1)
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default();
        let (up, down, own_vote) = score.get(&m.msg_id).copied().unwrap_or_default();
        *comment_count.entry(m.thread_id.to_owned()).or_default() += 1;
        comments.push(ChannelComment {
            id: m.msg_id.to_owned(),
            thread_id: m.thread_id.to_owned(),
            parent_id: m.parent_id.to_owned(),
            author_id: m.author_id.to_owned(),
            author_name,
            text,
            published: m.publish_ts,
            up,
            down,
            own_vote,
        });
    }

    // posts: of edited posts (same original id) only the newest version
    let mut newest: HashMap<String, &StoredMsg> = HashMap::new();
    for m in checked.iter().filter(|m| sub_type(&m.data) == SUBTYPE_POST && m.parent_id.is_empty()) {
        let orig = if m.orig_msg_id.is_empty() { m.msg_id.to_owned() } else { m.orig_msg_id.to_owned() };
        match newest.get(&orig) {
            Some(old) if old.publish_ts >= m.publish_ts => {}
            _ => {
                newest.insert(orig, m);
            }
        }
    }
    let mut posts: Vec<ChannelPost> = newest
        .into_values()
        .map(|m| {
            let mut post = ChannelPost {
                id: m.msg_id.to_owned(),
                orig_msg_id: m.orig_msg_id.to_owned(),
                title: m.name.to_owned(),
                text: String::new(),
                thumbnail: String::new(),
                files: vec![],
                published: m.publish_ts,
                unread: m.status & 0x04 != 0,
                // comments may point at this version or at the original post
                comments: comment_count.get(&m.msg_id).copied().unwrap_or_default()
                    + if !m.orig_msg_id.is_empty() && m.orig_msg_id != m.msg_id {
                        comment_count.get(&m.orig_msg_id).copied().unwrap_or_default()
                    } else {
                        0
                    },
            };
            for (ty, value) in tlvs(&m.data) {
                match ty {
                    0x0057 => post.text = String::from_utf8_lossy(value).into_owned(),
                    0x1001 => post.files = files(value),
                    0x1060 => post.thumbnail = data_url(image_bytes(value)),
                    _ => {}
                }
            }
            post
        })
        .collect();
    posts.sort_by(|a, b| b.published.cmp(&a.published));

    Ok(web::Json(json!({ "retval": true, "posts": posts, "comments": comments, "pending": pending })))
}

/// Ids of our own identities (we can sign with them).
async fn own_identity_ids(state: &DataCore) -> HashSet<String> {
    state
        .get_service_data()
        .gxs_id()
        .get_group_meta_all()
        .await
        .into_iter()
        .filter(|g| g.subscribe_flags.contains(SubscribeFlags::ADMIN))
        .map(|g| g.group_id.to_string())
        .collect()
}

// --- rsGxsChannels/createChannelV2 {name, description, thumbnail} ----------------

#[derive(Deserialize)]
pub struct CreateChannelIn {
    name: String,
    #[serde(default)]
    description: String,
    /// data URL or base64
    #[serde(default)]
    thumbnail: String,
}
#[post("/createChannelV2")]
pub async fn create_channel(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<CreateChannelIn>,
) -> Result<impl Responder> {
    let res: std::result::Result<String, String> = async {
        let picture = picture_from_page(&params.thumbnail)?;
        let group = crate::gxs::create_id::create_channel(&params.name, &params.description, &picture)?;
        let id = group.group_id.to_string();
        state
            .get_service_data()
            .gxs_channels()
            .store_new_group(group)
            .await
            .ok_or("could not store the channel")?;
        log::info!("created channel '{}' ({id})", params.name.trim());
        Ok(id)
    }
    .await;
    Ok(web::Json(match res {
        Ok(id) => json!({ "retval": true, "channelId": id, "errorMessage": "" }),
        Err(e) => json!({ "retval": false, "channelId": "", "errorMessage": e }),
    }))
}

/// Stores a message we made and returns its id.
async fn store_own(
    state: &DataCore,
    group_id: &GxsGroupId,
    (msg_id, data, meta): ([u8; 20], Vec<u8>, Vec<u8>),
    thread_id: &[u8; 20],
    parent_id: &[u8; 20],
    author: Option<&GxsId>,
    title: &str,
) -> std::result::Result<String, String> {
    let zero = [0u8; 20];
    let hex20 = |b: &[u8; 20]| if b == &zero { String::new() } else { hex::encode(b) };
    let now = now();
    let msg = StoredMsg {
        msg_id: hex::encode(msg_id),
        group_id: group_id.to_string(),
        thread_id: hex20(thread_id),
        parent_id: hex20(parent_id),
        orig_msg_id: hex::encode(msg_id),
        author_id: author.map(|a| a.to_string()).unwrap_or_default(),
        name: title.to_owned(),
        publish_ts: now,
        data,
        meta,
        recv_ts: now,
        status: 1,
        flags: 0,
    };
    if !state.get_service_data().gxs_channels().store_own_message(msg).await {
        return Err("could not store the message".into());
    }
    Ok(hex::encode(msg_id))
}

/// The channel, which must be subscribed (or ours).
async fn subscribed_channel(
    state: &DataCore,
    channel_id: &str,
) -> std::result::Result<(GxsGroupId, retroshare_compat::gxs::sqlite::types::GxsGroup), String> {
    let group_id = parse_group_id(channel_id).ok_or("invalid channel id")?;
    let group = state
        .get_service_data()
        .gxs_channels()
        .get_group_meta(&group_id)
        .await
        .ok_or("unknown channel")?;
    if !group.subscribe_flags.intersects(SubscribeFlags::SUBSCRIBED | SubscribeFlags::ADMIN) {
        return Err("subscribe to the channel first".into());
    }
    Ok((group_id, group))
}

// --- rsGxsChannels/createPostV2 {channelId, title, mBody, thumbnail} -------------
// Only with the channel's publish key (our own channels). No files yet: rustyshare
// has no file sharing.

#[derive(Deserialize)]
pub struct CreatePostIn {
    #[serde(rename = "channelId")]
    channel_id: String,
    title: String,
    #[serde(default, rename = "mBody")]
    body: String,
    #[serde(default)]
    thumbnail: String,
}
#[post("/createPostV2")]
pub async fn create_post(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<CreatePostIn>,
) -> Result<impl Responder> {
    let res: std::result::Result<String, String> = async {
        let (group_id, group) = subscribed_channel(&state, &params.channel_id).await?;
        let title = params.title.trim();
        if title.is_empty() {
            return Err("the post needs a title".to_string());
        }
        let publish_key = group
            .keys
            .private_keys
            .iter()
            .find(|k| k.key_flags.contains(TlvKeyFlags::DISTRIBUTE_PUBLISH))
            .ok_or("only the channel's owner can post")?
            .to_owned();
        let picture = picture_from_page(&params.thumbnail)?;

        // RsGxsChannelPostItem: text, file set (empty), thumbnail
        let mut body = tlv(0x0057, params.body.as_bytes());
        body.extend(tlv(0x1001, &[]));
        body.extend(crate::gxs::create_id::image_tlv(&picture));
        let zero = [0u8; 20];
        let msg = crate::gxs::create_id::create_signed_message(
            [0x02, 0x02, 0x17, SUBTYPE_POST],
            body,
            &group_id,
            &zero,
            &zero,
            None,
            Some(&publish_key),
            title,
        )?;
        // self check with the code that checks received posts
        let public = group
            .keys
            .public_keys
            .iter()
            .find(|k| k.key_flags.contains(TlvKeyFlags::DISTRIBUTE_PUBLISH))
            .ok_or("public publish key missing")?;
        if !crate::gxs::create_id::verify_msg_signature(&msg.2, &msg.1, public, KeySignType::IndexAuthenPublish)? {
            return Err("self check of the post signature failed".into());
        }
        let id = store_own(&state, &group_id, msg, &zero, &zero, None, title).await?;
        log::info!("created channel post {id} in {}", params.channel_id);
        Ok(id)
    }
    .await;
    Ok(web::Json(match res {
        Ok(id) => json!({ "retval": true, "postId": id, "errorMessage": "" }),
        Err(e) => json!({ "retval": false, "postId": "", "errorMessage": e }),
    }))
}

fn tlv(tag: u16, body: &[u8]) -> Vec<u8> {
    let mut out = tag.to_be_bytes().to_vec();
    out.extend(((body.len() + 6) as u32).to_be_bytes());
    out.extend(body);
    out
}

/// Private and public key of one of our identities.
async fn own_identity(
    state: &DataCore,
    author_id: &str,
) -> std::result::Result<
    (
        GxsId,
        retroshare_compat::tlv::tlv_keys::TlvPrivateRSAKey,
        retroshare_compat::tlv::tlv_keys::TlvPublicRSAKey,
    ),
    String,
> {
    let author = parse_gxs_id(author_id).ok_or("invalid identity")?;
    let ids = state.get_service_data().gxs_id();
    let private = ids.get_priv_keys_by_id(&author).await.ok_or("that identity is not one of yours")?;
    let public = ids.get_pub_keys_by_id(&author).await.ok_or("identity key missing")?;
    Ok((author, private, public))
}

// --- rsGxsChannels/createCommentV2 {channelId, threadId, comment, authorId, parentId}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCommentIn {
    channel_id: String,
    /// the post
    thread_id: String,
    comment: String,
    author_id: String,
    /// the post or the comment answered; empty = the post
    #[serde(default)]
    parent_id: String,
}
#[post("/createCommentV2")]
pub async fn create_comment(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<CreateCommentIn>,
) -> Result<impl Responder> {
    let res: std::result::Result<String, String> = async {
        let (group_id, _) = subscribed_channel(&state, &params.channel_id).await?;
        let text = params.comment.trim();
        if text.is_empty() {
            return Err("the comment is empty".to_string());
        }
        let thread = to20(&params.thread_id).ok_or("invalid post id")?;
        let parent = if params.parent_id.trim().is_empty() { thread } else { to20(&params.parent_id).ok_or("invalid parent id")? };
        let (author, private, public) = own_identity(&state, &params.author_id).await?;

        // RsGxsCommentItem: the comment as string TLV of type 1
        let msg = crate::gxs::create_id::create_signed_message(
            [0x02, 0x02, 0x17, SUBTYPE_COMMENT],
            tlv(1, text.as_bytes()),
            &group_id,
            &thread,
            &parent,
            Some((&author, &private)),
            None,
            "",
        )?;
        if !crate::gxs::create_id::verify_msg_author_signature(&msg.2, &msg.1, &public)? {
            return Err("self check of the comment signature failed".into());
        }
        let id = store_own(&state, &group_id, msg, &thread, &parent, Some(&author), "").await?;
        log::info!("created channel comment {id} in {}", params.channel_id);
        Ok(id)
    }
    .await;
    Ok(web::Json(match res {
        Ok(id) => json!({ "retval": true, "commentMessageId": id, "errorMessage": "" }),
        Err(e) => json!({ "retval": false, "commentMessageId": "", "errorMessage": e }),
    }))
}

// --- rsGxsChannels/createVoteV2 {channelId, postId, commentId, authorId, vote} ----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVoteIn {
    channel_id: String,
    post_id: String,
    comment_id: String,
    author_id: String,
    /// RsGxsVoteType: 1 down, 2 up
    vote: u32,
}
#[post("/createVoteV2")]
pub async fn create_vote(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<CreateVoteIn>,
) -> Result<impl Responder> {
    let res: std::result::Result<String, String> = async {
        if !matches!(params.vote, VOTE_UP | VOTE_DOWN) {
            return Err("invalid vote".to_string());
        }
        let (group_id, _) = subscribed_channel(&state, &params.channel_id).await?;
        let thread = to20(&params.post_id).ok_or("invalid post id")?;
        let parent = to20(&params.comment_id).ok_or("invalid comment id")?;
        let (author, private, public) = own_identity(&state, &params.author_id).await?;
        let msg = crate::gxs::create_id::create_signed_message(
            [0x02, 0x02, 0x17, SUBTYPE_VOTE],
            params.vote.to_be_bytes().to_vec(),
            &group_id,
            &thread,
            &parent,
            Some((&author, &private)),
            None,
            "",
        )?;
        if !crate::gxs::create_id::verify_msg_author_signature(&msg.2, &msg.1, &public)? {
            return Err("self check of the vote signature failed".into());
        }
        store_own(&state, &group_id, msg, &thread, &parent, Some(&author), "").await
    }
    .await;
    Ok(web::Json(match res {
        Ok(id) => json!({ "retval": true, "voteId": id, "errorMessage": "" }),
        Err(e) => json!({ "retval": false, "voteId": "", "errorMessage": e }),
    }))
}

// --- read status, unread counts, sync period (like the forum calls) ---------------

#[derive(Deserialize)]
pub struct MarkReadIn {
    #[serde(rename = "msgIds")]
    msg_ids: Vec<String>,
    #[serde(default = "default_true")]
    read: bool,
}
fn default_true() -> bool {
    true
}
// rsGxsChannels/markRead (rustyshare): {channelId, msgIds, read}
#[post("/markRead")]
pub async fn mark_read(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<MarkReadIn>,
) -> Result<impl Responder> {
    let list: Vec<_> = params
        .msg_ids
        .iter()
        .filter(|id| id.len() == 40 && id.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|id| (id.to_lowercase(), if params.read { 2 } else { 3 }))
        .collect();
    state.get_service_data().gxs_channels().set_message_status(list).await;
    Ok(web::Json(RetVal { retval: true }))
}

// rsGxsChannels/getChannelsUnread (rustyshare): {retval: {channelId: count}}
#[post("/getChannelsUnread")]
pub async fn get_unread(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    let counts: HashMap<String, i64> =
        state.get_service_data().gxs_channels().unread_counts().await.into_iter().collect();
    Ok(web::Json(RetVal { retval: counts }))
}

#[derive(Deserialize)]
pub struct SyncPeriodIn {
    #[serde(rename = "channelId")]
    channel_id: String,
    #[serde(default, rename = "ageInSecs")]
    age_in_secs: u32,
}
// rsGxsChannels/getSyncPeriod / setSyncPeriod {channelId, ageInSecs}
#[post("/getSyncPeriod")]
pub async fn get_sync_period(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SyncPeriodIn>,
) -> Result<impl Responder> {
    let secs = match parse_group_id(&params.channel_id) {
        Some(id) => state.get_service_data().gxs_channels().get_sync_period(&id).await,
        None => None,
    };
    Ok(web::Json(RetVal { retval: secs }))
}
#[post("/setSyncPeriod")]
pub async fn set_sync_period(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SyncPeriodIn>,
) -> Result<impl Responder> {
    let ok = match parse_group_id(&params.channel_id) {
        Some(id) => state.get_service_data().gxs_channels().set_sync_period(&id, params.age_in_secs).await,
        None => false,
    };
    Ok(web::Json(RetVal { retval: ok }))
}

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsGxsChannels")
        .service(get_channels_summaries)
        .service(get_channel_info)
        .service(subscribe_to_channel)
        .service(get_channel_all_content)
        .service(create_channel)
        .service(create_post)
        .service(create_comment)
        .service(create_vote)
        .service(mark_read)
        .service(get_unread)
        .service(get_sync_period)
        .service(set_sync_period)
}
