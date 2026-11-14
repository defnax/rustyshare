//! rsMail JSON API, like libretroshare's `retroshare/rsmail.h` (RetroShare's JSON API
//! serves it as /rsMail/...): mail between friends. See `mail.rs` and
//! `services/mail.rs`.

use std::{collections::BTreeSet, sync::Arc};

use actix_web::{post, web, Responder, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    mail::{self, api_flags, box_of, flags, Address, Mail, MsgItem, OutInfo},
    model::DataCore,
};

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or_default()
}

/// Rs::Mail::MsgAddress as RetroShare's JSON API writes it
fn address(a: &Address) -> Value {
    json!({ "_type": a.ty, "_mode": a.mode, "_addr_string": a.addr })
}

/// All destinations of a mail (to / cc / bcc, nodes and identities).
fn destinations(m: &MsgItem) -> Vec<Value> {
    let mut out = vec![];
    for (list, ty, mode) in [
        (&m.peers_to, Address::TYPE_PEER, 1),
        (&m.peers_cc, Address::TYPE_PEER, 2),
        (&m.peers_bcc, Address::TYPE_PEER, 3),
        (&m.gxs_to, Address::TYPE_GXS, 1),
        (&m.gxs_cc, Address::TYPE_GXS, 2),
        (&m.gxs_bcc, Address::TYPE_GXS, 3),
    ] {
        for id in list {
            out.push(json!({ "_type": ty, "_mode": mode, "_addr_string": hex::encode(id) }));
        }
    }
    out
}

/// Files suggested in the mail (RsTlvFileSet): name, size, hash.
fn files(m: &MsgItem) -> Vec<Value> {
    let d = &m.attachment;
    let mut out = vec![];
    let mut pos = 6;
    while pos + 6 <= d.len() {
        let ty = u16::from_be_bytes([d[pos], d[pos + 1]]);
        let len = u32::from_be_bytes([d[pos + 2], d[pos + 3], d[pos + 4], d[pos + 5]]) as usize;
        if len < 6 || pos + len > d.len() {
            break;
        }
        if ty == 0x1000 && len >= 34 {
            let it = &d[pos + 6..pos + len];
            let size = u64::from_be_bytes(it[0..8].try_into().unwrap_or_default());
            let hash = hex::encode(&it[8..28]);
            let mut name = String::new();
            let mut p = 28;
            while p + 6 <= it.len() {
                let t = u16::from_be_bytes([it[p], it[p + 1]]);
                let l = u32::from_be_bytes([it[p + 2], it[p + 3], it[p + 4], it[p + 5]]) as usize;
                if l < 6 || p + l > it.len() {
                    break;
                }
                if t == 0x0051 {
                    name = String::from_utf8_lossy(&it[p + 6..p + l]).into_owned();
                }
                p += l;
            }
            out.push(json!({ "fname": name, "size": size, "hash": hash }));
        }
        pos += len;
    }
    out
}

/// MsgInfoSummary
fn summary(id: u32, m: &Mail, from: &Address, to: &Address, f: u32) -> Value {
    let ts = mail_time(m, f);
    json!({
        "msgId": id.to_string(),
        "from": address(from),
        "to": address(to),
        "msgflags": api_flags(f),
        "msgtags": m.tags.iter().collect::<Vec<_>>(),
        "title": m.msg.subject,
        "count": files(&m.msg).len(),
        "ts": ts,
        "destinations": destinations(&m.msg),
        // rustyshare: start of the text for the card view
        "snippet": snippet(&m.msg.message, 180),
    })
}

/// Plain text from the (HTML) mail body: tags left out, common entities decoded,
/// white space collapsed, at most `max` characters.
fn snippet(html: &str, max: usize) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    let lower = html.to_ascii_lowercase();
    // skip <head> and <style> blocks of Qt rich text
    let mut skip_until: Option<&str> = None;
    let mut i = 0;
    let bytes = html.as_bytes();
    while i < bytes.len() {
        if let Some(end) = skip_until {
            match lower[i..].find(end) {
                Some(p) => {
                    i += p + end.len();
                    skip_until = None;
                    continue;
                }
                None => break,
            }
        }
        let c = html[i..].chars().next().unwrap_or(' ');
        if c == '<' {
            if lower[i..].starts_with("<style") {
                skip_until = Some("</style>");
                continue;
            }
            if lower[i..].starts_with("<head") {
                skip_until = Some("</head>");
                continue;
            }
            in_tag = true;
            text.push(' ');
        } else if c == '>' && in_tag {
            in_tag = false;
        } else if !in_tag {
            text.push(c);
        }
        i += c.len_utf8();
    }
    let text = text
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    let words: Vec<&str> = text.split_whitespace().collect();
    let joined = words.join(" ");
    match joined.char_indices().nth(max) {
        Some((cut, _)) => format!("{}…", &joined[..cut]),
        None => joined,
    }
}

/// Sent mails show when they were sent, received ones when they arrived.
fn mail_time(m: &Mail, f: u32) -> u32 {
    if f & flags::OUTGOING != 0 {
        m.msg.send_time
    } else {
        m.msg.recv_time.max(m.msg.send_time)
    }
}

// --- rsMail/getMessageSummaries {box} ---------------------------------------------
// BoxName: 1 inbox, 2 outbox, 3 drafts, 4 sent, 5 trash, 6 all

#[derive(Deserialize)]
pub struct BoxIn {
    #[serde(rename = "box")]
    box_name: u8,
}
#[post("/getMessageSummaries")]
pub async fn get_message_summaries(params: web::Json<BoxIn>) -> Result<impl Responder> {
    let Some(store) = mail::store() else {
        return Ok(web::Json(json!({ "retval": false, "msgList": [] })));
    };
    let want = params.box_name;
    let mut list = vec![];
    if want == 2 {
        // the outbox: one entry per destination still waiting
        for (id, copies) in &store.outgoing {
            let Some(m) = store.mails.get(id) else { continue };
            for (sub, info) in copies {
                list.push(summary(*sub, m, &info.origin, &info.destination, info.flags | flags::PENDING));
            }
        }
    } else {
        for (id, m) in &store.mails {
            let b = box_of(m);
            if want == 6 || want == b {
                list.push(summary(*id, m, &m.from, &m.to, m.msg.flags));
            }
        }
    }
    Ok(web::Json(json!({ "retval": true, "msgList": list })))
}

// --- rsMail/getMessage {msgId} ----------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MsgIdIn {
    msg_id: String,
}
#[post("/getMessage")]
pub async fn get_message(params: web::Json<MsgIdIn>) -> Result<impl Responder> {
    let fail = || web::Json(json!({ "retval": false }));
    let Ok(id) = params.msg_id.trim().parse::<u32>() else { return Ok(fail()) };
    let Some(store) = mail::store() else { return Ok(fail()) };
    // a stored mail, or an outbox copy of one
    let found = store.mails.get(&id).map(|m| (m, m.from.clone(), m.to.clone(), m.msg.flags)).or_else(|| {
        store.outgoing.iter().find_map(|(orig, copies)| {
            let info = copies.get(&id)?;
            let m = store.mails.get(orig)?;
            Some((m, info.origin.clone(), info.destination.clone(), info.flags | flags::PENDING))
        })
    });
    let Some((m, from, to, f)) = found else { return Ok(fail()) };
    let files = files(&m.msg);
    let size: u64 = files.iter().filter_map(|f| f["size"].as_u64()).sum();
    let ts = mail_time(m, f);
    let parent = if m.parent_id == 0 { String::new() } else { m.parent_id.to_string() };
    Ok(web::Json(json!({ "retval": true, "msg": {
        "msgId": id.to_string(),
        "from": address(&from),
        "to": address(&to),
        "destinations": destinations(&m.msg),
        "msgflags": api_flags(f),
        "title": m.msg.subject,
        "msg": m.msg.message,
        "attach_title": "",
        "attach_comment": "",
        "files": files,
        "size": size,
        "count": files.len(),
        "ts": ts,
        "msgtags": m.tags.iter().collect::<Vec<_>>(),
        "parentId": parent,
    }})))
}

// --- rsMail/getMessageCount -------------------------------------------------------

#[post("/getMessageCount")]
pub async fn get_message_count() -> Result<impl Responder> {
    let Some(store) = mail::store() else {
        return Ok(web::Json(json!({ "nInbox": 0, "nInboxNew": 0, "nOutbox": 0, "nDraftbox": 0, "nSentbox": 0, "nTrashbox": 0 })));
    };
    let (mut inbox, mut new, mut drafts, mut sent, mut trash) = (0, 0, 0, 0, 0);
    for m in store.mails.values() {
        match box_of(m) {
            1 => {
                inbox += 1;
                if m.msg.flags & (flags::NEW | flags::UNREAD_BY_USER) != 0 {
                    new += 1;
                }
            }
            3 => drafts += 1,
            4 => sent += 1,
            _ => trash += 1,
        }
    }
    let outbox: usize = store.outgoing.values().map(|c| c.len()).sum();
    Ok(web::Json(json!({ "nInbox": inbox, "nInboxNew": new, "nOutbox": outbox,
        "nDraftbox": drafts, "nSentbox": sent, "nTrashbox": trash })))
}

// --- rsMail/MessageSend {info} ----------------------------------------------------
// info: {title, msg, destinations: [{_type: 1, _mode: 1|2|3, _addr_string: <ssl id>}],
//        msgParentId (rustyshare, optional: replied / forwarded mail)}

#[derive(Deserialize)]
pub struct AddressIn {
    #[serde(rename = "_type")]
    ty: u32,
    #[serde(rename = "_mode")]
    mode: u32,
    #[serde(rename = "_addr_string")]
    addr: String,
}
#[derive(Deserialize)]
pub struct InfoIn {
    /// sender: our node, or one of our identities (needed for distant mail)
    #[serde(default)]
    from: Option<AddressIn>,
    #[serde(default)]
    title: String,
    #[serde(default)]
    msg: String,
    #[serde(default)]
    destinations: Vec<AddressIn>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendIn {
    info: InfoIn,
    /// the draft this mail was written in (removed after sending)
    #[serde(default)]
    draft_id: String,
}

fn id16(hex_id: &str) -> Option<[u8; 16]> {
    hex::decode(hex_id.trim()).ok()?.try_into().ok()
}

/// p3MsgService::initMIRsMsg()
fn new_msg(info: &InfoIn) -> std::result::Result<MsgItem, String> {
    let mut m = MsgItem { send_time: now(), subject: info.title.clone(), message: info.msg.clone(), ..Default::default() };
    for d in &info.destinations {
        if d.ty == Address::TYPE_GXS {
            let id = id16(&d.addr).ok_or("invalid identity id")?;
            match d.mode {
                2 => m.gxs_cc.push(id),
                3 => m.gxs_bcc.push(id),
                _ => m.gxs_to.push(id),
            }
            continue;
        }
        if d.ty != Address::TYPE_PEER {
            return Err("unknown kind of address".into());
        }
        let id = id16(&d.addr).ok_or("invalid friend id")?;
        match d.mode {
            2 => m.peers_cc.push(id),
            3 => m.peers_bcc.push(id),
            _ => m.peers_to.push(id),
        }
    }
    for list in [&mut m.peers_to, &mut m.peers_cc, &mut m.peers_bcc, &mut m.gxs_to, &mut m.gxs_cc, &mut m.gxs_bcc] {
        list.sort();
        list.dedup();
    }
    Ok(m)
}

#[post("/MessageSend")]
pub async fn message_send(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SendIn>,
) -> Result<impl Responder> {
    let own = state.get_own_location().get_location_id().to_string();
    let own_ids = crate::webui::channels::own_identity_ids(&state).await;
    let res = (|| -> std::result::Result<String, String> {
        let info = &params.info;
        if info.destinations.is_empty() {
            return Err("add at least one friend".to_string());
        }
        if info.title.trim().is_empty() {
            return Err("the mail needs a subject".to_string());
        }
        let mut msg = new_msg(info)?;
        // distant mail is sent (and signed) by one of our identities
        let from_gxs = info.from.as_ref().filter(|f| f.ty == Address::TYPE_GXS).map(|f| f.addr.trim().to_lowercase());
        let has_gxs = info.destinations.iter().any(|d| d.ty == Address::TYPE_GXS);
        if has_gxs {
            let Some(f) = &from_gxs else {
                return Err("choose one of your identities to send mail to identities".to_string());
            };
            if !own_ids.contains(f) {
                return Err("the sender is not one of your identities".to_string());
            }
        }
        let mut store = mail::store().ok_or("mail not loaded")?;

        // p3MsgService::MessageSend(): stored as sent (OUTGOING, PENDING until all
        // destinations got it) plus one outbox entry per destination
        let id = store.new_id();
        msg.msg_id = id;
        msg.recv_time = now();
        msg.flags = flags::OUTGOING | flags::PENDING;
        let from = match &from_gxs {
            Some(g) => Address::gxs(g, 1),
            None => Address::peer(&own, 1),
        };
        let mut dests: Vec<Address> = vec![];
        for d in &info.destinations {
            let a = if d.ty == Address::TYPE_GXS {
                Address::gxs(&d.addr, d.mode.clamp(1, 3))
            } else {
                Address::peer(&d.addr, d.mode.clamp(1, 3))
            };
            if !dests.iter().any(|x| x.addr == a.addr) {
                dests.push(a);
            }
        }
        for dest in dests {
            let sub = store.new_id();
            // friends get it from our node, identities from our identity
            let origin = if dest.ty == Address::TYPE_GXS { from.clone() } else { Address::peer(&own, 1) };
            store.outgoing.entry(id).or_default().insert(
                sub,
                OutInfo {
                    origin,
                    destination: dest,
                    flags: flags::OUTGOING | flags::LOAD_EMBEDDED_IMAGES,
                    grouter_id: 0,
                },
            );
        }
        store.mails.insert(id, Mail { from, to: Address::default(), msg, ..Default::default() });
        if let Ok(draft) = params.draft_id.trim().parse::<u32>() {
            if store.mails.get(&draft).map(|m| m.msg.flags & flags::DRAFT != 0).unwrap_or(false) {
                store.mails.remove(&draft);
            }
        }
        store.save();
        Ok(id.to_string())
    })();
    mail::outbox_changed();
    Ok(web::Json(match res {
        Ok(id) => json!({ "retval": true, "msgId": id, "errorMessage": "" }),
        Err(e) => json!({ "retval": false, "errorMessage": e }),
    }))
}

// --- rsMail/MessageToDraft {info, msgParentId} ------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftIn {
    info: InfoIn,
    /// replace this draft
    #[serde(default)]
    draft_id: String,
}
#[post("/MessageToDraft")]
pub async fn message_to_draft(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<DraftIn>,
) -> Result<impl Responder> {
    let own = state.get_own_location().get_location_id().to_string();
    let res = (|| -> std::result::Result<String, String> {
        let mut msg = new_msg(&params.info)?;
        let from = match params.info.from.as_ref().filter(|f| f.ty == Address::TYPE_GXS) {
            Some(f) => Address::gxs(&f.addr, 1),
            None => Address::peer(&own, 1),
        };
        let mut store = mail::store().ok_or("mail not loaded")?;
        let id = match params.draft_id.trim().parse::<u32>() {
            Ok(d) if store.mails.contains_key(&d) => d,
            _ => store.new_id(),
        };
        msg.msg_id = id;
        msg.flags = flags::OUTGOING | flags::DRAFT;
        store.mails.insert(id, Mail { from, msg, ..Default::default() });
        store.save();
        Ok(id.to_string())
    })();
    Ok(web::Json(match res {
        Ok(id) => json!({ "retval": true, "msgId": id }),
        Err(e) => json!({ "retval": false, "errorMessage": e }),
    }))
}

/// Changes the flags of a stored mail; false when it does not exist.
fn set_flags(id: &str, set: u32, clear: u32) -> bool {
    let Ok(id) = id.trim().parse::<u32>() else { return false };
    let Some(mut store) = mail::store() else { return false };
    let Some(m) = store.mails.get_mut(&id) else { return false };
    let before = m.msg.flags;
    m.msg.flags = (m.msg.flags & !clear) | set;
    if m.msg.flags != before {
        store.save();
    }
    true
}

// rsMail/MessageRead {msgId, unreadByUser}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadIn {
    msg_id: String,
    #[serde(default)]
    unread_by_user: bool,
}
#[post("/MessageRead")]
pub async fn message_read(params: web::Json<ReadIn>) -> Result<impl Responder> {
    let ok = if params.unread_by_user {
        set_flags(&params.msg_id, flags::UNREAD_BY_USER, flags::NEW)
    } else {
        set_flags(&params.msg_id, 0, flags::NEW | flags::UNREAD_BY_USER)
    };
    Ok(web::Json(json!({ "retval": ok })))
}

// rsMail/MessageToTrash {msgId, bTrash}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashIn {
    msg_id: String,
    b_trash: bool,
}
#[post("/MessageToTrash")]
pub async fn message_to_trash(params: web::Json<TrashIn>) -> Result<impl Responder> {
    let ok = if params.b_trash {
        set_flags(&params.msg_id, flags::TRASH, 0)
    } else {
        set_flags(&params.msg_id, 0, flags::TRASH)
    };
    Ok(web::Json(json!({ "retval": ok })))
}

// rsMail/MessageDelete {msgId}: gone for good (also from the outbox)
#[post("/MessageDelete")]
pub async fn message_delete(params: web::Json<MsgIdIn>) -> Result<impl Responder> {
    let Ok(id) = params.msg_id.trim().parse::<u32>() else {
        return Ok(web::Json(json!({ "retval": false })));
    };
    let Some(mut store) = mail::store() else { return Ok(web::Json(json!({ "retval": false }))) };
    let mut ok = store.mails.remove(&id).is_some();
    ok |= store.outgoing.remove(&id).is_some();
    // an outbox copy: only that destination
    let orig = store.outgoing.iter().find(|(_, c)| c.contains_key(&id)).map(|(o, _)| *o);
    if let Some(orig) = orig {
        if let Some(c) = store.outgoing.get_mut(&orig) {
            c.remove(&id);
            if c.is_empty() {
                store.outgoing.remove(&orig);
                if let Some(m) = store.mails.get_mut(&orig) {
                    m.msg.flags &= !flags::PENDING;
                }
            }
        }
        ok = true;
    }
    if ok {
        store.save();
    }
    Ok(web::Json(json!({ "retval": ok })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkIn {
    msg_id: String,
    #[serde(default, alias = "replied", alias = "forwarded")]
    mark: bool,
}
// rsMail/MessageStar {msgId, mark}
#[post("/MessageStar")]
pub async fn message_star(params: web::Json<MarkIn>) -> Result<impl Responder> {
    let ok = if params.mark { set_flags(&params.msg_id, flags::STAR, 0) } else { set_flags(&params.msg_id, 0, flags::STAR) };
    Ok(web::Json(json!({ "retval": ok })))
}
// rsMail/MessageReplied {msgId, replied}
#[post("/MessageReplied")]
pub async fn message_replied(params: web::Json<MarkIn>) -> Result<impl Responder> {
    let ok = if params.mark { set_flags(&params.msg_id, flags::REPLIED, 0) } else { set_flags(&params.msg_id, 0, flags::REPLIED) };
    Ok(web::Json(json!({ "retval": ok })))
}
// rsMail/MessageForwarded {msgId, forwarded}
#[post("/MessageForwarded")]
pub async fn message_forwarded(params: web::Json<MarkIn>) -> Result<impl Responder> {
    let ok = if params.mark { set_flags(&params.msg_id, flags::FORWARDED, 0) } else { set_flags(&params.msg_id, 0, flags::FORWARDED) };
    Ok(web::Json(json!({ "retval": ok })))
}

// rsMail/getMessageTagTypes -> {retval, tags: {types: [{key, value: {first, second}}]}}
#[post("/getMessageTagTypes")]
pub async fn get_message_tag_types() -> Result<impl Responder> {
    let types: Vec<Value> = mail::store()
        .map(|s| {
            s.tags
                .iter()
                .map(|(id, (text, color))| json!({ "key": id, "value": { "first": text, "second": color } }))
                .collect()
        })
        .unwrap_or_default();
    Ok(web::Json(json!({ "retval": true, "tags": { "types": types } })))
}

// rsMail/setMessageTag {msgId, tagId, set}; tagId 0 with set false removes all tags
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TagIn {
    msg_id: String,
    tag_id: u32,
    set: bool,
}
#[post("/setMessageTag")]
pub async fn set_message_tag(params: web::Json<TagIn>) -> Result<impl Responder> {
    let Ok(id) = params.msg_id.trim().parse::<u32>() else {
        return Ok(web::Json(json!({ "retval": false })));
    };
    let Some(mut store) = mail::store() else { return Ok(web::Json(json!({ "retval": false }))) };
    let known: BTreeSet<u32> = store.tags.keys().copied().collect();
    let Some(m) = store.mails.get_mut(&id) else { return Ok(web::Json(json!({ "retval": false }))) };
    if params.set {
        if !known.contains(&params.tag_id) {
            return Ok(web::Json(json!({ "retval": false })));
        }
        m.tags.insert(params.tag_id);
    } else if params.tag_id == 0 {
        m.tags.clear();
    } else {
        m.tags.remove(&params.tag_id);
    }
    store.save();
    Ok(web::Json(json!({ "retval": true })))
}

// rsMail/getDistantMessagingPermissionFlags, setDistantMessagingPermissionFlags {flags}:
// 0 everybody, 1 contacts only, 2 nobody (RS_DISTANT_MESSAGING_CONTACT_PERMISSION_FLAG_*)
#[post("/getDistantMessagingPermissionFlags")]
pub async fn get_distant_permission() -> Result<impl Responder> {
    Ok(web::Json(json!({ "retval": crate::services::grouter::permission() })))
}
#[derive(Deserialize)]
pub struct FlagsIn {
    flags: u32,
}
#[post("/setDistantMessagingPermissionFlags")]
pub async fn set_distant_permission(params: web::Json<FlagsIn>) -> Result<impl Responder> {
    let ok = crate::services::grouter::command(crate::services::grouter::GRouterCmd::SetPermission(params.flags));
    Ok(web::Json(json!({ "retval": ok })))
}

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsMail")
        .service(get_distant_permission)
        .service(set_distant_permission)
        .service(get_message_summaries)
        .service(get_message)
        .service(get_message_count)
        .service(message_send)
        .service(message_to_draft)
        .service(message_read)
        .service(message_to_trash)
        .service(message_delete)
        .service(message_star)
        .service(message_replied)
        .service(message_forwarded)
        .service(get_message_tag_types)
        .service(set_message_tag)
}
