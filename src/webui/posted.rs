//! rsPosted JSON API (boards), like libretroshare's `retroshare/rsposted.h`:
//! board list, subscribe, posts (link, text, picture) with votes and scores,
//! comments, creating boards, posts, comments and votes.
//!
//! Item formats (libretroshare rsitems/rsposteditems.cc, rsgxscommentitems.h):
//! - group  `RsGxsPostedGroupItem` (0x02): description (TLV 0x00b3), optional picture
//!   (TLV 0x1060, only written when there is one)
//! - post   `RsGxsPostedPostItem`  (0x03): link (TLV 0x0059), notes (TLV 0x0057),
//!   optional picture (TLV 0x1060); author signed (boards have no publish key check)
//! - comment `RsGxsCommentItem` (0xf1) and vote `RsGxsVoteItem` (0xf2) like channels;
//!   a vote for a post has the post as thread and parent
//!
//! Scores like `RsPostedPost::calculateScores()`: top = up - down, hot = top divided
//! (or multiplied when not positive) by (2 + age in hours)^1.5, new = -age.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use actix_web::{post, web, Responder, Result};
use retroshare_compat::{
    basics::{GxsGroupId, GxsId},
    gxs::sqlite::{database::StoredMsg, types::SubscribeFlags},
    tlv::tlv_keys::TlvKeyFlags,
    webui::identity::GxsGroupMeta,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    model::DataCore,
    webui::{
        channels::{
            data_url, image_bytes, now, own_identity, own_identity_ids, parse_group_id, parse_gxs_id,
            picture_from_page, sub_type, tlv, tlvs, to20, waited_too_long, Check,
        },
        RetVal,
    },
};

const SUBTYPE_POST: u8 = 0x03;
const SUBTYPE_COMMENT: u8 = 0xf1;
const SUBTYPE_VOTE: u8 = 0xf2;
/// RsGxsVoteType
const VOTE_DOWN: u32 = 1;
const VOTE_UP: u32 = 2;
/// RsItem header start: version 2, service 0x0216
const HEADER: [u8; 3] = [0x02, 0x02, 0x16];

fn header(sub: u8) -> [u8; 4] {
    [HEADER[0], HEADER[1], HEADER[2], sub]
}

// --- rsPosted/getBoardsSummaries ---------------------------------------------------

#[post("/getBoardsSummaries")]
pub async fn get_boards_summaries(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    let store = state.get_service_data().gxs_posted();
    let stats: HashMap<String, (u32, u32, u32)> = store
        .group_stats()
        .await
        .into_iter()
        .map(|(id, posts, last, pop)| (id, (posts, last, pop)))
        .collect();
    let boards: Vec<GxsGroupMeta> = store
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
    Ok(web::Json(json!({ "retval": true, "groupInfo": boards })))
}

// --- rsPosted/getBoardInfo (rustyshare): one board with its picture ------------------

#[derive(Deserialize)]
pub struct BoardIn {
    #[serde(rename = "boardId")]
    board_id: String,
}
#[derive(Serialize, Default)]
pub struct BoardInfo {
    id: String,
    name: String,
    description: String,
    /// data URL, empty when the board has no picture
    image: String,
    created: i64,
    last_post: i64,
    subscribed: bool,
    own: bool,
    received_from: String,
}
#[post("/getBoardInfo")]
pub async fn get_board_info(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<BoardIn>,
) -> Result<impl Responder> {
    let fail = || web::Json(json!({ "retval": false }));
    let Some(group_id) = parse_group_id(&params.board_id) else { return Ok(fail()) };
    let Some(group) = state.get_service_data().gxs_posted().get_group_with_data(&group_id).await else {
        return Ok(fail());
    };
    let data = group.get_blobs().nxs_data;
    let mut info = BoardInfo {
        id: group.group_id.to_string(),
        name: group.group_name.to_owned(),
        created: group.publish_ts,
        last_post: group.last_post,
        subscribed: group.subscribe_flags.contains(SubscribeFlags::SUBSCRIBED),
        own: group.subscribe_flags.contains(SubscribeFlags::ADMIN)
            || group.keys.private_keys.iter().any(|k| k.key_flags.contains(TlvKeyFlags::DISTRIBUTE_ADMIN)),
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

// --- rsPosted/subscribeToBoard {boardId, subscribe} ----------------------------------

#[derive(Deserialize)]
pub struct SubscribeIn {
    #[serde(rename = "boardId")]
    board_id: String,
    subscribe: bool,
}
#[post("/subscribeToBoard")]
pub async fn subscribe_to_board(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SubscribeIn>,
) -> Result<impl Responder> {
    let ok = match parse_group_id(&params.board_id) {
        Some(id) => state.get_service_data().gxs_posted().subscribe(&id, params.subscribe).await,
        None => false,
    };
    Ok(web::Json(RetVal { retval: ok }))
}

// --- rsPosted/getBoardAllContent {boardId} -------------------------------------------
// The verified posts, comments and votes of a board. Everything needs the author's
// identity signature (author unknown: requested, the message waits; wrong signature:
// deleted). Banned authors are left out.

#[derive(Serialize)]
pub struct BoardPost {
    id: String,
    orig_msg_id: String,
    title: String,
    link: String,
    notes: String,
    /// data URL
    image: String,
    author_id: String,
    author_name: String,
    published: i64,
    unread: bool,
    comments: usize,
    up: u32,
    down: u32,
    /// our vote: 0 none, 1 down, 2 up
    own_vote: u32,
    hot: f64,
    top: f64,
    new: f64,
}
#[derive(Serialize)]
pub struct BoardComment {
    id: String,
    thread_id: String,
    parent_id: String,
    author_id: String,
    author_name: String,
    text: String,
    published: i64,
    up: u32,
    down: u32,
    own_vote: u32,
}

/// RsPostedPost::calculateScores(): (hot, top, new)
fn scores(up: u32, down: u32, age_secs: i64) -> (f64, f64, f64) {
    let top = up as f64 - down as f64;
    let factor = (2.0 + age_secs.max(0) as f64 / 3600.0).powf(1.5);
    let hot = if top > 0.0 { top / factor } else { top * factor };
    (hot, top, -(age_secs as f64))
}

#[post("/getBoardAllContent")]
pub async fn get_board_all_content(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<BoardIn>,
) -> Result<impl Responder> {
    let Some(group_id) = parse_group_id(&params.board_id) else {
        return Ok(web::Json(json!({ "retval": false })));
    };
    let boards = state.get_service_data().gxs_posted();
    let ids = state.get_service_data().gxs_id();

    let msgs = boards.get_messages(&group_id).await;
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
        } else {
            match parse_gxs_id(&msg.author_id) {
                None => Check::Bad, // board messages need an author
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
                log::warn!("board message {} has a wrong or missing signature, deleted", msg.msg_id);
                status_updates.push((msg.msg_id.to_owned(), -1));
            }
        }
    }
    boards.set_message_status(status_updates).await;

    // votes: per voted message (post or comment) and author, the newest one counts
    let own_ids: HashSet<String> = own_identity_ids(&state).await;
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
        let author_name = name_of(&mut names, ids, &m.author_id).await;
        let text = tlvs(&m.data)
            .into_iter()
            .find(|(t, _)| *t == 1)
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default();
        let (up, down, own_vote) = score.get(&m.msg_id).copied().unwrap_or_default();
        *comment_count.entry(m.thread_id.to_owned()).or_default() += 1;
        comments.push(BoardComment {
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
        if state.reputation_is_banned(&m.author_id) {
            continue;
        }
        let orig = if m.orig_msg_id.is_empty() { m.msg_id.to_owned() } else { m.orig_msg_id.to_owned() };
        match newest.get(&orig) {
            Some(old) if old.publish_ts >= m.publish_ts => {}
            _ => {
                newest.insert(orig, m);
            }
        }
    }
    let now = now();
    let mut posts: Vec<BoardPost> = vec![];
    for m in newest.into_values() {
        // votes and comments may point at this version or at the original post
        let mut ids_of_post = vec![m.msg_id.to_owned()];
        if !m.orig_msg_id.is_empty() && m.orig_msg_id != m.msg_id {
            ids_of_post.push(m.orig_msg_id.to_owned());
        }
        let (mut up, mut down, mut own_vote, mut count) = (0, 0, 0, 0);
        for id in &ids_of_post {
            let (u, d, o) = score.get(id).copied().unwrap_or_default();
            up += u;
            down += d;
            if o != 0 {
                own_vote = o;
            }
            count += comment_count.get(id).copied().unwrap_or_default();
        }
        let (hot, top, new) = scores(up, down, now - m.publish_ts);
        let mut post = BoardPost {
            id: m.msg_id.to_owned(),
            orig_msg_id: m.orig_msg_id.to_owned(),
            title: m.name.to_owned(),
            link: String::new(),
            notes: String::new(),
            image: String::new(),
            author_id: m.author_id.to_owned(),
            author_name: name_of(&mut names, ids, &m.author_id).await,
            published: m.publish_ts,
            unread: m.status & 0x04 != 0,
            comments: count,
            up,
            down,
            own_vote,
            hot,
            top,
            new,
        };
        for (ty, value) in tlvs(&m.data) {
            match ty {
                0x0059 => post.link = String::from_utf8_lossy(value).into_owned(),
                0x0057 => post.notes = String::from_utf8_lossy(value).into_owned(),
                0x1060 => post.image = data_url(image_bytes(value)),
                _ => {}
            }
        }
        posts.push(post);
    }
    posts.sort_by(|a, b| b.published.cmp(&a.published));

    Ok(web::Json(json!({ "retval": true, "posts": posts, "comments": comments, "pending": pending })))
}

// --- rsPosted/createBoardV2 {board_name, board_description, board_image} -------------

#[derive(Deserialize)]
pub struct CreateBoardIn {
    #[serde(alias = "name")]
    board_name: String,
    #[serde(default, alias = "description")]
    board_description: String,
    /// data URL or base64
    #[serde(default, alias = "image")]
    board_image: String,
}
#[post("/createBoardV2")]
pub async fn create_board(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<CreateBoardIn>,
) -> Result<impl Responder> {
    let res: std::result::Result<String, String> = async {
        let picture = picture_from_page(&params.board_image)?;
        let group = crate::gxs::create_id::create_board(&params.board_name, &params.board_description, &picture)?;
        let id = group.group_id.to_string();
        state
            .get_service_data()
            .gxs_posted()
            .store_new_group(group)
            .await
            .ok_or("could not store the board")?;
        log::info!("created board '{}' ({id})", params.board_name.trim());
        Ok(id)
    }
    .await;
    Ok(web::Json(match res {
        Ok(id) => json!({ "retval": true, "boardId": id, "errorMessage": "" }),
        Err(e) => json!({ "retval": false, "boardId": "", "errorMessage": e }),
    }))
}

/// An identity's name, looked up once per request.
async fn name_of(
    names: &mut HashMap<String, String>,
    ids: &crate::model::services::gxs_id::GxsIdStore,
    author: &str,
) -> String {
    if let Some(n) = names.get(author) {
        return n.to_owned();
    }
    let n = match parse_gxs_id(author) {
        Some(a) => ids.get_group_meta(&a.into()).await.map(|g| g.group_name).unwrap_or_default(),
        None => String::new(),
    };
    names.insert(author.to_owned(), n.to_owned());
    n
}

/// Stores a message we made and returns its id.
async fn store_own(
    state: &DataCore,
    group_id: &GxsGroupId,
    (msg_id, data, meta): ([u8; 20], Vec<u8>, Vec<u8>),
    thread_id: &[u8; 20],
    parent_id: &[u8; 20],
    author: &GxsId,
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
        author_id: author.to_string(),
        name: title.to_owned(),
        publish_ts: now,
        data,
        meta,
        recv_ts: now,
        status: 1,
        flags: 0,
    };
    if !state.get_service_data().gxs_posted().store_own_message(msg).await {
        return Err("could not store the message".into());
    }
    Ok(hex::encode(msg_id))
}

/// The board, which must be subscribed (or ours).
async fn subscribed_board(state: &DataCore, board_id: &str) -> std::result::Result<GxsGroupId, String> {
    let group_id = parse_group_id(board_id).ok_or("invalid board id")?;
    let group = state
        .get_service_data()
        .gxs_posted()
        .get_group_meta(&group_id)
        .await
        .ok_or("unknown board")?;
    if !group.subscribe_flags.intersects(SubscribeFlags::SUBSCRIBED | SubscribeFlags::ADMIN) {
        return Err("subscribe to the board first".into());
    }
    Ok(group_id)
}

/// Signs with one of our identities, checks the result and stores it.
async fn sign_and_store(
    state: &DataCore,
    group_id: &GxsGroupId,
    sub: u8,
    body: Vec<u8>,
    thread: &[u8; 20],
    parent: &[u8; 20],
    author_id: &str,
    title: &str,
) -> std::result::Result<String, String> {
    let (author, private, public) = own_identity(state, author_id).await?;
    let msg = crate::gxs::create_id::create_signed_message(
        header(sub),
        body,
        group_id,
        thread,
        parent,
        Some((&author, &private)),
        None,
        title,
    )?;
    if !crate::gxs::create_id::verify_msg_author_signature(&msg.2, &msg.1, &public)? {
        return Err("self check of the signature failed".into());
    }
    store_own(state, group_id, msg, thread, parent, &author, title).await
}

// --- rsPosted/createPostV2 {boardId, title, link, notes, authorId, image} -------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePostIn {
    board_id: String,
    title: String,
    #[serde(default)]
    link: String,
    #[serde(default)]
    notes: String,
    author_id: String,
    /// data URL or base64
    #[serde(default)]
    image: String,
}
#[post("/createPostV2")]
pub async fn create_post(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<CreatePostIn>,
) -> Result<impl Responder> {
    let res: std::result::Result<String, String> = async {
        let group_id = subscribed_board(&state, &params.board_id).await?;
        let title = params.title.trim();
        if title.is_empty() {
            return Err("the post needs a title".to_string());
        }
        let link = params.link.trim();
        if !link.is_empty() && !(link.starts_with("http://") || link.starts_with("https://") || link.starts_with("retroshare://")) {
            return Err("the link must start with http:// or https://".to_string());
        }
        let picture = picture_from_page(&params.image)?;

        // RsGxsPostedPostItem: link, notes, picture (only when there is one)
        let mut body = tlv(0x0059, link.as_bytes());
        body.extend(tlv(0x0057, params.notes.as_bytes()));
        if !picture.is_empty() {
            body.extend(crate::gxs::create_id::image_tlv(&picture));
        }
        let zero = [0u8; 20];
        let id = sign_and_store(&state, &group_id, SUBTYPE_POST, body, &zero, &zero, &params.author_id, title).await?;
        log::info!("created board post {id} in {}", params.board_id);
        Ok(id)
    }
    .await;
    Ok(web::Json(match res {
        Ok(id) => json!({ "retval": true, "postId": id, "error_message": "" }),
        Err(e) => json!({ "retval": false, "postId": "", "error_message": e }),
    }))
}

// --- rsPosted/createCommentV2 {boardId, postId, comment, authorId, parentId} ---------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCommentIn {
    board_id: String,
    post_id: String,
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
        let group_id = subscribed_board(&state, &params.board_id).await?;
        let text = params.comment.trim();
        if text.is_empty() {
            return Err("the comment is empty".to_string());
        }
        let thread = to20(&params.post_id).ok_or("invalid post id")?;
        let parent = if params.parent_id.trim().is_empty() { thread } else { to20(&params.parent_id).ok_or("invalid parent id")? };
        let id = sign_and_store(&state, &group_id, SUBTYPE_COMMENT, tlv(1, text.as_bytes()), &thread, &parent, &params.author_id, "").await?;
        log::info!("created board comment {id} in {}", params.board_id);
        Ok(id)
    }
    .await;
    Ok(web::Json(match res {
        Ok(id) => json!({ "retval": true, "commentMessageId": id, "errorMessage": "" }),
        Err(e) => json!({ "retval": false, "commentMessageId": "", "errorMessage": e }),
    }))
}

// --- rsPosted/voteForPost {postGrpId, postMsgId, authorId, vote} ---------------------
// --- rsPosted/voteForComment {boardId, postMsgId, commentMsgId, authorId, vote} ------
// Like RetroShare: one vote per identity and message.

async fn vote(
    state: &DataCore,
    board_id: &str,
    post_id: &str,
    target_id: &str,
    author_id: &str,
    vote: u32,
) -> std::result::Result<String, String> {
    if !matches!(vote, VOTE_UP | VOTE_DOWN) {
        return Err("invalid vote".to_string());
    }
    let group_id = subscribed_board(state, board_id).await?;
    let thread = to20(post_id).ok_or("invalid post id")?;
    let parent = to20(target_id).ok_or("invalid message id")?;
    let author = parse_gxs_id(author_id).ok_or("invalid identity")?.to_string();
    let target = hex::encode(parent);
    let already = state.get_service_data().gxs_posted().get_messages(&group_id).await.into_iter().any(|m| {
        sub_type(&m.data) == SUBTYPE_VOTE && m.parent_id == target && m.author_id == author
    });
    if already {
        return Err("you already voted for this".into());
    }
    sign_and_store(state, &group_id, SUBTYPE_VOTE, vote.to_be_bytes().to_vec(), &thread, &parent, author_id, "").await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VotePostIn {
    post_grp_id: String,
    post_msg_id: String,
    author_id: String,
    vote: u32,
}
#[post("/voteForPost")]
pub async fn vote_for_post(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<VotePostIn>,
) -> Result<impl Responder> {
    let res = vote(&state, &params.post_grp_id, &params.post_msg_id, &params.post_msg_id, &params.author_id, params.vote).await;
    Ok(web::Json(match res {
        Ok(id) => json!({ "retval": true, "voteId": id, "errorMessage": "" }),
        Err(e) => json!({ "retval": false, "voteId": "", "errorMessage": e }),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoteCommentIn {
    board_id: String,
    post_msg_id: String,
    comment_msg_id: String,
    author_id: String,
    vote: u32,
}
#[post("/voteForComment")]
pub async fn vote_for_comment(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<VoteCommentIn>,
) -> Result<impl Responder> {
    let res = vote(&state, &params.board_id, &params.post_msg_id, &params.comment_msg_id, &params.author_id, params.vote).await;
    Ok(web::Json(match res {
        Ok(id) => json!({ "retval": true, "voteId": id, "errorMessage": "" }),
        Err(e) => json!({ "retval": false, "voteId": "", "errorMessage": e }),
    }))
}

// --- read status, unread counts, sync period ------------------------------------------

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
// rsPosted/markRead (rustyshare): {msgIds, read}
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
    state.get_service_data().gxs_posted().set_message_status(list).await;
    Ok(web::Json(RetVal { retval: true }))
}

// rsPosted/getBoardsUnread (rustyshare): {retval: {boardId: count}}, posts only
#[post("/getBoardsUnread")]
pub async fn get_unread(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    let counts: HashMap<String, i64> =
        state.get_service_data().gxs_posted().unread_post_counts().await.into_iter().collect();
    Ok(web::Json(RetVal { retval: counts }))
}

#[derive(Deserialize)]
pub struct SyncPeriodIn {
    #[serde(rename = "boardId")]
    board_id: String,
    #[serde(default, rename = "ageInSecs")]
    age_in_secs: u32,
}
#[post("/getSyncPeriod")]
pub async fn get_sync_period(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SyncPeriodIn>,
) -> Result<impl Responder> {
    let secs = match parse_group_id(&params.board_id) {
        Some(id) => state.get_service_data().gxs_posted().get_sync_period(&id).await,
        None => None,
    };
    Ok(web::Json(RetVal { retval: secs }))
}
#[post("/setSyncPeriod")]
pub async fn set_sync_period(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SyncPeriodIn>,
) -> Result<impl Responder> {
    let ok = match parse_group_id(&params.board_id) {
        Some(id) => state.get_service_data().gxs_posted().set_sync_period(&id, params.age_in_secs).await,
        None => false,
    };
    Ok(web::Json(RetVal { retval: ok }))
}

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsPosted")
        .service(get_boards_summaries)
        .service(get_board_info)
        .service(subscribe_to_board)
        .service(get_board_all_content)
        .service(create_board)
        .service(create_post)
        .service(create_comment)
        .service(vote_for_post)
        .service(vote_for_comment)
        .service(mark_read)
        .service(get_unread)
        .service(get_sync_period)
        .service(set_sync_period)
}
