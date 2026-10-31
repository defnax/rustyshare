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
    let forums = state
        .get_service_data()
        .gxs_forums()
        .get_group_meta_all()
        .await
        .into_iter()
        .map(|g| g.into())
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
        if msg.status != 1 {
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
                    // identity not known yet: asking for it happened in get_pub_keys_by_id
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

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsGxsForums")
        .service(rs_gxs_forums_get_forums_summaries)
        .service(rs_gxs_forums_get_forum_info)
        .service(rs_gxs_forums_subscribe_to_forum)
        .service(rs_gxs_forums_get_forum_posts)
}
