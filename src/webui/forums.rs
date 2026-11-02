//! rsGxsForums JSON API (libretroshare retroshare/rsgxsforums.h), first part:
//! the forum list. Posts follow with GXS message sync.

use std::sync::Arc;

use actix_web::{post, web, Responder, Result};
use retroshare_compat::{
    basics::GxsGroupId,
    gxs::sqlite::types::SubscribeFlags,
    webui::identity::GxsGroupMeta,
};
use serde::{Deserialize, Serialize};

use crate::model::DataCore;

// rsGxsForums/getForumsSummaries
#[derive(Serialize)]
pub struct ForumsSummaries {
    retval: bool,
    forums: Vec<GxsGroupMeta>,
}
#[post("/getForumsSummaries")]
pub async fn rs_gxs_forums_get_forums_summaries(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    let store = state.get_service_data().gxs_forums();
    // like RetroShare: post count, last post and popularity (friends that have the
    // forum) come from the friends' group statistics (RsNxsSyncGrpStatsItem)
    let stats: std::collections::HashMap<String, (u32, u32, u32)> = store
        .group_stats()
        .await
        .into_iter()
        .map(|(id, posts, last, pop)| (id, (posts, last, pop)))
        .collect();
    let forums = store
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
    Ok(web::Json(ForumsSummaries {
        retval: true,
        forums,
    }))
}

/// Description from the forum's group data (`RsGxsForumGroupItem`: item header, then
/// the description as a TLV string).
fn forum_description(data: &[u8]) -> String {
    let Some(len) = data
        .get(10..14)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    else {
        return String::new();
    };
    if len < 6 {
        return String::new();
    }
    data.get(14..8 + len)
        .map(|b| String::from_utf8_lossy(b).to_string())
        .unwrap_or_default()
}

// rsGxsForums/getForumInfo (rustyshare specific): details of one forum
#[derive(Deserialize)]
pub struct ForumInfoIn {
    #[serde(rename = "forumId")]
    forum_id: String,
}
#[derive(Serialize, Default)]
pub struct ForumInfo {
    id: String,
    name: String,
    description: String,
    /// unix seconds
    created: i64,
    last_post: i64,
    subscribed: bool,
    own: bool,
    author: String,
    received_from: String,
}
#[derive(Serialize)]
pub struct ForumInfoOut {
    retval: bool,
    info: ForumInfo,
}
#[post("/getForumInfo")]
pub async fn rs_gxs_forums_get_forum_info(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<ForumInfoIn>,
) -> Result<impl Responder> {
    let fail = || web::Json(ForumInfoOut { retval: false, info: ForumInfo::default() });
    let group_id = match hex::decode(params.forum_id.trim()) {
        Ok(bytes) if bytes.len() == 16 => GxsGroupId::from(bytes),
        _ => return Ok(fail()),
    };
    let Some(group) = state
        .get_service_data()
        .gxs_forums()
        .get_group_with_data(&group_id)
        .await
    else {
        return Ok(fail());
    };

    let info = ForumInfo {
        id: params.forum_id.trim().to_lowercase(),
        name: group.group_name.to_owned(),
        description: forum_description(&group.get_blobs().nxs_data),
        created: group.publish_ts,
        last_post: group.last_post,
        subscribed: group.subscribe_flags.contains(SubscribeFlags::SUBSCRIBED),
        own: group.subscribe_flags.contains(SubscribeFlags::ADMIN),
        author: if group.author_id == Default::default() {
            String::new()
        } else {
            group.author_id.to_string()
        },
        received_from: if group.originator == Default::default() {
            String::new()
        } else {
            group.originator.to_string()
        },
    };
    Ok(web::Json(ForumInfoOut { retval: true, info }))
}

// rsGxsForums/subscribeToForum {forumId, subscribe}, like RetroShare
#[derive(Deserialize)]
pub struct SubscribeIn {
    #[serde(rename = "forumId")]
    forum_id: String,
    subscribe: bool,
}
#[post("/subscribeToForum")]
pub async fn rs_gxs_forums_subscribe_to_forum(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SubscribeIn>,
) -> Result<impl Responder> {
    let ok = match parse_group_id(&params.forum_id) {
        Some(id) => state.get_service_data().gxs_forums().subscribe(&id, params.subscribe).await,
        None => false,
    };
    Ok(web::Json(crate::webui::RetVal { retval: ok }))
}

fn parse_group_id(id: &str) -> Option<GxsGroupId> {
    match hex::decode(id.trim()) {
        Ok(bytes) if bytes.len() == 16 => Some(GxsGroupId::from(bytes)),
        _ => None,
    }
}

/// When we first tried to verify a post whose author identity is unknown (msg id ->
/// unix time). RetroShare waits 60 s; rustyshare 2 minutes, since identities are only
/// requested when a forum is shown.
fn waited_too_long(msg_id: &str) -> bool {
    use std::sync::{Mutex, OnceLock};
    static FIRST_TRY: OnceLock<Mutex<std::collections::HashMap<String, i64>>> = OnceLock::new();
    const MAX_WAIT: i64 = 120;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    let mut map = FIRST_TRY.get_or_init(Default::default).lock().expect("lock poisoned");
    let first = *map.entry(msg_id.to_owned()).or_insert(now);
    if now - first > MAX_WAIT {
        map.remove(msg_id);
        true
    } else {
        false
    }
}

/// Text of a forum post (`RsGxsForumMsgItem`: item header, then the message as a TLV
/// string, HTML).
fn post_text(data: &[u8]) -> String {
    forum_description(data)
}

// rsGxsForums/getForumPosts (rustyshare specific): the verified posts of a forum.
// Signatures are checked here like GxsSecurity::validateNxsMsg(): posts whose author
// identity isn't known yet stay hidden (the identity is requested from friends),
// posts with a wrong signature are deleted, posts by banned authors are not shown.
#[derive(Serialize)]
pub struct ForumPost {
    id: String,
    thread_id: String,
    parent_id: String,
    orig_msg_id: String,
    author_id: String,
    author_name: String,
    title: String,
    text: String,
    /// unix seconds
    published: i64,
    unread: bool,
}
#[derive(Serialize)]
pub struct ForumPostsOut {
    retval: bool,
    posts: Vec<ForumPost>,
    /// posts still waiting for their author's identity
    pending: usize,
}
#[post("/getForumPosts")]
pub async fn rs_gxs_forums_get_forum_posts(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<ForumInfoIn>,
) -> Result<impl Responder> {
    let Some(group_id) = parse_group_id(&params.forum_id) else {
        return Ok(web::Json(ForumPostsOut { retval: false, posts: vec![], pending: 0 }));
    };
    let forums = state.get_service_data().gxs_forums();
    let ids = state.get_service_data().gxs_id();
    let msgs = forums.get_messages(&group_id).await;

    let mut names: std::collections::HashMap<String, String> = Default::default();
    let mut status_updates = vec![];
    let mut posts = vec![];
    let mut pending = 0;
    let mut waiting_for: Vec<String> = vec![];

    for msg in msgs {
        if msg.author_id.is_empty() {
            // forums require an author signature (RetroShare's authen policy)
            status_updates.push((msg.msg_id.to_owned(), -1));
            continue;
        }
        let author: retroshare_compat::basics::GxsId = match hex::decode(&msg.author_id) {
            Ok(b) if b.len() == 16 => b.into(),
            _ => continue,
        };
        if msg.status & 1 != 1 {
            match ids.get_pub_keys_by_id(&author).await {
                Some(key) => match crate::gxs::create_id::verify_msg_author_signature(&msg.meta, &msg.data, &key) {
                    Ok(true) => status_updates.push((msg.msg_id.to_owned(), 1)),
                    Ok(false) => {
                        log::warn!("forum post {} has a wrong author signature, deleted", msg.msg_id);
                        status_updates.push((msg.msg_id.to_owned(), -1));
                        continue;
                    }
                    Err(err) => {
                        log::warn!("forum post {} can't be verified ({err}), deleted", msg.msg_id);
                        status_updates.push((msg.msg_id.to_owned(), -1));
                        continue;
                    }
                },
                None => {
                    // identity not known yet: asking for it happened in get_pub_keys_by_id.
                    // Like RetroShare (VALIDATE_MAX_WAITING_TIME), give up after a while:
                    // the post is rejected and not requested again for a day.
                    if waited_too_long(&msg.msg_id) {
                        log::info!("forum post {}: author {} not found, rejected", msg.msg_id, msg.author_id);
                        status_updates.push((msg.msg_id.to_owned(), -1));
                        continue;
                    }
                    pending += 1;
                    if waiting_for.len() < 10 && !waiting_for.contains(&msg.author_id) {
                        waiting_for.push(msg.author_id.to_owned());
                    }
                    continue;
                }
            }
        }
        if state.reputation_is_banned(&msg.author_id) {
            continue;
        }
        let author_name = match names.get(&msg.author_id) {
            Some(n) => n.to_owned(),
            None => {
                let n = ids
                    .get_group_meta(&author.into())
                    .await
                    .map(|g| g.group_name)
                    .unwrap_or_default();
                names.insert(msg.author_id.to_owned(), n.to_owned());
                n
            }
        };
        posts.push(ForumPost {
            id: msg.msg_id.to_owned(),
            thread_id: msg.thread_id.to_owned(),
            parent_id: msg.parent_id.to_owned(),
            orig_msg_id: msg.orig_msg_id.to_owned(),
            author_id: msg.author_id.to_owned(),
            author_name,
            title: msg.name.to_owned(),
            text: post_text(&msg.data),
            published: msg.publish_ts,
            unread: msg.status & 0x04 != 0,
        });
    }
    forums.set_message_status(status_updates).await;
    if pending > 0 {
        log::info!(
            "{pending} posts in forum {} wait for their author identities, e.g. {}",
            params.forum_id,
            waiting_for.join(", ")
        );
    }

    Ok(web::Json(ForumPostsOut { retval: true, posts, pending }))
}

// rsGxsForums/createPost, like RetroShare:
// {forumId, title, mBody, authorId, parentId} -> {retval, postMsgId, errorMessage}
#[derive(Deserialize)]
pub struct CreatePostIn {
    #[serde(rename = "forumId")]
    forum_id: String,
    title: String,
    #[serde(rename = "mBody")]
    body: String,
    #[serde(rename = "authorId")]
    author_id: String,
    #[serde(default, rename = "parentId")]
    parent_id: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePostOut {
    retval: bool,
    post_msg_id: String,
    error_message: String,
}
#[post("/createPost")]
pub async fn rs_gxs_forums_create_post(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<CreatePostIn>,
) -> Result<impl Responder> {
    let out = |res: std::result::Result<String, String>| {
        web::Json(match res {
            Ok(id) => CreatePostOut { retval: true, post_msg_id: id, error_message: String::new() },
            Err(e) => CreatePostOut { retval: false, post_msg_id: String::new(), error_message: e },
        })
    };
    Ok(out(create_post(&state, &params).await))
}

async fn create_post(state: &DataCore, p: &CreatePostIn) -> std::result::Result<String, String> {
    let group_id = parse_group_id(&p.forum_id).ok_or("invalid forum id")?;
    if p.title.trim().is_empty() {
        return Err("the post needs a title".into());
    }
    let forums = state.get_service_data().gxs_forums();
    let ids = state.get_service_data().gxs_id();

    let forum = forums.get_group_meta(&group_id).await.ok_or("unknown forum")?;
    if !forum.subscribe_flags.intersects(SubscribeFlags::SUBSCRIBED | SubscribeFlags::ADMIN) {
        return Err("subscribe to the forum first".into());
    }

    let author: retroshare_compat::basics::GxsId = match hex::decode(p.author_id.trim()) {
        Ok(b) if b.len() == 16 => b.into(),
        _ => return Err("invalid identity".into()),
    };
    let private_key = ids
        .get_priv_keys_by_id(&author)
        .await
        .ok_or("that identity is not one of yours")?;
    let public_key = ids.get_pub_keys_by_id(&author).await.ok_or("identity key missing")?;

    // reply: thread = the parent's thread, or the parent itself when it starts one
    let zero = [0u8; 20];
    let (thread_id, parent_id) = if p.parent_id.trim().is_empty() {
        (zero, zero)
    } else {
        let parent_hex = p.parent_id.trim().to_lowercase();
        let msgs = forums.get_messages(&group_id).await;
        let parent = msgs.iter().find(|m| m.msg_id == parent_hex).ok_or("post to reply to not found")?;
        let thread_hex = if parent.thread_id.is_empty() { parent.msg_id.to_owned() } else { parent.thread_id.to_owned() };
        let to20 = |h: &str| -> Option<[u8; 20]> { hex::decode(h).ok()?.try_into().ok() };
        (
            to20(&thread_hex).ok_or("broken thread id")?,
            to20(&parent.msg_id).ok_or("broken parent id")?,
        )
    };

    // RsGxsForumMsgItem: version 2, service 0x0215, sub type 0x03
    let (msg_id, data, meta) = crate::gxs::create_id::create_message(
        [0x02, 0x02, 0x15, 0x03],
        &group_id,
        &thread_id,
        &parent_id,
        &author,
        &private_key,
        p.title.trim(),
        &p.body,
    )?;
    // self check with the same code that checks received posts
    if !crate::gxs::create_id::verify_msg_author_signature(&meta, &data, &public_key)? {
        return Err("self check of the post signature failed".into());
    }

    let hex20 = |b: &[u8; 20]| hex::encode(b);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    let msg = retroshare_compat::gxs::sqlite::database::StoredMsg {
        msg_id: hex20(&msg_id),
        group_id: group_id.to_string(),
        thread_id: if thread_id == zero { String::new() } else { hex20(&thread_id) },
        parent_id: if parent_id == zero { String::new() } else { hex20(&parent_id) },
        orig_msg_id: hex20(&msg_id),
        author_id: author.to_string(),
        name: p.title.trim().to_owned(),
        publish_ts: now,
        data,
        meta,
        recv_ts: now,
        status: 1,
        flags: 0,
    };
    if !forums.store_own_message(msg).await {
        return Err("could not store the post".into());
    }
    log::info!("created forum post {} in {}", hex20(&msg_id), p.forum_id);
    Ok(hex20(&msg_id))
}

// rsGxsForums/getForumsUnread (rustyshare specific): {retval: {forumId: count}}
#[post("/getForumsUnread")]
pub async fn rs_gxs_forums_get_unread(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    let counts: std::collections::HashMap<String, i64> =
        state.get_service_data().gxs_forums().unread_counts().await.into_iter().collect();
    Ok(web::Json(crate::webui::RetVal { retval: counts }))
}

// rsGxsForums/markRead (rustyshare): {forumId, msgIds: [...]} marks posts as read
#[derive(Deserialize)]
pub struct MarkReadIn {
    #[serde(rename = "forumId")]
    #[allow(dead_code)]
    forum_id: String,
    #[serde(rename = "msgIds")]
    msg_ids: Vec<String>,
}
#[post("/markRead")]
pub async fn rs_gxs_forums_mark_read(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<MarkReadIn>,
) -> Result<impl Responder> {
    let list: Vec<_> = params
        .msg_ids
        .iter()
        .filter(|id| id.len() == 40 && id.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|id| (id.to_lowercase(), 2))
        .collect();
    state.get_service_data().gxs_forums().set_message_status(list).await;
    Ok(web::Json(crate::webui::RetVal { retval: true }))
}

// rsGxsForums/getSyncPeriod / setSyncPeriod {forumId, ageInSecs} (0 = all), like
// RetroShare's per-group "synchronise posts of the last ..." setting
#[derive(Deserialize)]
pub struct SyncPeriodIn {
    #[serde(rename = "forumId")]
    forum_id: String,
    #[serde(default, rename = "ageInSecs")]
    age_in_secs: u32,
}
#[post("/getSyncPeriod")]
pub async fn rs_gxs_forums_get_sync_period(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SyncPeriodIn>,
) -> Result<impl Responder> {
    let secs = match parse_group_id(&params.forum_id) {
        Some(id) => state.get_service_data().gxs_forums().get_sync_period(&id).await,
        None => None,
    };
    Ok(web::Json(crate::webui::RetVal { retval: secs }))
}
#[post("/setSyncPeriod")]
pub async fn rs_gxs_forums_set_sync_period(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SyncPeriodIn>,
) -> Result<impl Responder> {
    let ok = match parse_group_id(&params.forum_id) {
        Some(id) => state.get_service_data().gxs_forums().set_sync_period(&id, params.age_in_secs).await,
        None => false,
    };
    Ok(web::Json(crate::webui::RetVal { retval: ok }))
}

// rsGxsForums/createForumV2, like RetroShare (public forum, no author or moderators
// yet): {name, description} -> {retval, forumId, errorMessage}
#[derive(Deserialize)]
pub struct CreateForumIn {
    name: String,
    #[serde(default)]
    description: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateForumOut {
    retval: bool,
    forum_id: String,
    error_message: String,
}
#[post("/createForumV2")]
pub async fn rs_gxs_forums_create_forum(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<CreateForumIn>,
) -> Result<impl Responder> {
    let res = match crate::gxs::create_id::create_forum(&params.name, &params.description) {
        Ok(group) => {
            let id = group.group_id.to_string();
            match state.get_service_data().gxs_forums().store_new_group(group).await {
                Some(_) => {
                    log::info!("created forum '{}' ({id})", params.name.trim());
                    Ok(id)
                }
                None => Err("could not store the forum".to_string()),
            }
        }
        Err(e) => Err(e),
    };
    Ok(web::Json(match res {
        Ok(forum_id) => CreateForumOut { retval: true, forum_id, error_message: String::new() },
        Err(error_message) => CreateForumOut { retval: false, forum_id: String::new(), error_message },
    }))
}

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsGxsForums")
        .service(rs_gxs_forums_get_forums_summaries)
        .service(rs_gxs_forums_get_forum_info)
        .service(rs_gxs_forums_subscribe_to_forum)
        .service(rs_gxs_forums_get_forum_posts)
        .service(rs_gxs_forums_create_post)
        .service(rs_gxs_forums_get_unread)
        .service(rs_gxs_forums_mark_read)
        .service(rs_gxs_forums_get_sync_period)
        .service(rs_gxs_forums_set_sync_period)
        .service(rs_gxs_forums_create_forum)
}
