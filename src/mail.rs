//! Mail between friends, like libretroshare's p3MsgService (service 0x0013, "msg").
//!
//! The mail is kept in RetroShare's own `config/msgs.cfg`, so RetroShare and rustyshare
//! see the same mailbox:
//! - `RsMailStorageItem` (sub type 0x0a): from, to, tags, parent id and the `RsMsgItem`
//!   (with its message id, config serialisation)
//! - `RsMsgOutgoingMapStorageItem` (0x0b): the outbox, one entry per destination
//! - `RsMsgTagType` (0x03): tag names and colours
//! - everything else (distant mail maps, settings) is written back unchanged
//!
//! Safety: every item that is read is written again and compared with the original
//! bytes. Only when all of them match (and the file has no old-format items) does
//! rustyshare write `msgs.cfg`; otherwise it keeps its mail in `rustyshare_msgs.cfg`
//! (same format) and leaves RetroShare's file alone.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use byteorder::{ByteOrder, NetworkEndian};
use log::{info, warn};
use tokio::sync::Notify;

use crate::retroshare_compat::{config_store, ssl_key::SslKey};

const FILE: &str = "msgs.cfg";
const FALLBACK_FILE: &str = "rustyshare_msgs.cfg";
const HEADER_SIZE: usize = 8;

/// RS_PKT_VERSION_SERVICE, RS_SERVICE_TYPE_MSG (0x0013)
const ITEM_PREFIX: [u8; 3] = [0x02, 0x00, 0x13];
pub const SUBTYPE_MSG: u8 = 0x01;
const SUBTYPE_TAG_TYPE: u8 = 0x03;
const SUBTYPE_MAIL_STORAGE: u8 = 0x0a;
const SUBTYPE_OUTGOING_MAP: u8 = 0x0b;
/// old formats, converted by RetroShare when it loads them
const OLD_SUBTYPES: [u8; 4] = [0x01, 0x04, 0x05, 0x06];

const TLV_STR_NAME: u16 = 0x0051;
const TLV_STR_MSG: u16 = 0x0057;
const TLV_STR_SUBJECT: u16 = 0x0058;
const TLV_FILESET: u16 = 0x1001;
const TLV_PEERSET: u16 = 0x1021;
const TLV_GXSIDSET: u16 = 0x1025;

/// RS_MSG_FLAGS_* (stored / sent flags)
pub mod flags {
    pub const OUTGOING: u32 = 0x0000_0001;
    pub const PENDING: u32 = 0x0000_0002;
    pub const DRAFT: u32 = 0x0000_0004;
    pub const NEW: u32 = 0x0000_0010;
    pub const TRASH: u32 = 0x0000_0020;
    pub const UNREAD_BY_USER: u32 = 0x0000_0040;
    pub const REPLIED: u32 = 0x0000_0080;
    pub const FORWARDED: u32 = 0x0000_0100;
    pub const STAR: u32 = 0x0000_0200;
    pub const PARTIAL: u32 = 0x0000_0400;
    pub const USER_REQUEST: u32 = 0x0000_0800;
    pub const FRIEND_RECOMMENDATION: u32 = 0x0000_1000;
    pub const DISTANT: u32 = 0x0000_8000;
    pub const SIGNATURE_CHECKS: u32 = 0x0001_0000;
    pub const SIGNED: u32 = 0x0002_0000;
    pub const LOAD_EMBEDDED_IMAGES: u32 = 0x0004_0000;
    pub const PUBLISH_KEY: u32 = 0x0020_0000;
    pub const SPAM: u32 = 0x0040_0000;
    pub const SYSTEM: u32 = USER_REQUEST | FRIEND_RECOMMENDATION | PUBLISH_KEY;
}

/// RS_MSG_* flags of the JSON API (rsmail.h), different values than the stored ones
pub fn api_flags(f: u32) -> u32 {
    let map: [(u32, u32); 16] = [
        (flags::DISTANT, 0x001000),
        (flags::SIGNED, 0x004000),
        (flags::SIGNATURE_CHECKS, 0x002000),
        (flags::OUTGOING, 0x0001),
        (flags::PENDING, 0x0002),
        (flags::DRAFT, 0x0004),
        (flags::NEW, 0x0010),
        (flags::TRASH, 0x0020),
        (flags::UNREAD_BY_USER, 0x0040),
        (flags::REPLIED, 0x0080),
        (flags::FORWARDED, 0x0100),
        (flags::STAR, 0x0200),
        (flags::SPAM, 0x040000),
        (flags::USER_REQUEST, 0x0400),
        (flags::FRIEND_RECOMMENDATION, 0x0800),
        (flags::LOAD_EMBEDDED_IMAGES, 0x008000),
    ];
    map.iter().filter(|(s, _)| f & s != 0).fold(0, |acc, (_, a)| acc | a)
}

/// Rs::Mail::MsgAddress
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Address {
    /// 1 = node (SSL id), 2 = GXS id, 3 = plain
    pub ty: u32,
    /// 1 = to, 2 = cc, 3 = bcc
    pub mode: u32,
    pub addr: String,
}

impl Address {
    pub const TYPE_PEER: u32 = 1;
    pub const TYPE_GXS: u32 = 2;
    pub fn peer(id: &str, mode: u32) -> Self {
        Address { ty: Self::TYPE_PEER, mode, addr: id.to_lowercase() }
    }
}

/// RsMsgItem
#[derive(Debug, Clone, Default)]
pub struct MsgItem {
    pub flags: u32,
    pub send_time: u32,
    pub recv_time: u32,
    pub subject: String,
    pub message: String,
    pub peers_to: Vec<[u8; 16]>,
    pub peers_cc: Vec<[u8; 16]>,
    pub peers_bcc: Vec<[u8; 16]>,
    pub gxs_to: Vec<[u8; 16]>,
    pub gxs_cc: Vec<[u8; 16]>,
    pub gxs_bcc: Vec<[u8; 16]>,
    /// RsTlvFileSet, kept as is (with its TLV header)
    pub attachment: Vec<u8>,
    /// only in the config file
    pub msg_id: u32,
}

/// RsMailStorageItem
#[derive(Debug, Clone, Default)]
pub struct Mail {
    pub from: Address,
    pub to: Address,
    pub tags: BTreeSet<u32>,
    pub parent_id: u32,
    pub msg: MsgItem,
}

/// RsOutgoingMessageInfo
#[derive(Debug, Clone, Default)]
pub struct OutInfo {
    pub origin: Address,
    pub destination: Address,
    pub flags: u32,
    pub grouter_id: u64,
}

// --- reading ---------------------------------------------------------------------

struct Reader<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Option<u32> {
        let v = NetworkEndian::read_u32(self.d.get(self.pos..self.pos + 4)?);
        self.pos += 4;
        Some(v)
    }
    fn u64(&mut self) -> Option<u64> {
        let v = NetworkEndian::read_u64(self.d.get(self.pos..self.pos + 8)?);
        self.pos += 8;
        Some(v)
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let v = self.d.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(v)
    }
    /// std::string: u32 length + bytes
    fn raw_string(&mut self) -> Option<String> {
        let n = self.u32()? as usize;
        Some(String::from_utf8_lossy(self.bytes(n)?).into_owned())
    }
    /// TLV: (type, value)
    fn tlv(&mut self) -> Option<(u16, &'a [u8])> {
        let head = self.d.get(self.pos..self.pos + 6)?;
        let ty = NetworkEndian::read_u16(&head[0..2]);
        let len = NetworkEndian::read_u32(&head[2..6]) as usize;
        if len < 6 {
            return None;
        }
        let value = self.d.get(self.pos + 6..self.pos.checked_add(len)?)?;
        self.pos += len;
        Some((ty, value))
    }
    fn tlv_string(&mut self, want: u16) -> Option<String> {
        let (ty, v) = self.tlv()?;
        (ty == want).then(|| String::from_utf8_lossy(v).into_owned())
    }
    fn tlv_ids(&mut self, want: u16) -> Option<Vec<[u8; 16]>> {
        let (ty, v) = self.tlv()?;
        if ty != want || v.len() % 16 != 0 {
            return None;
        }
        Some(v.chunks(16).map(|c| c.try_into().unwrap_or_default()).collect())
    }
    /// a whole TLV including its header
    fn tlv_raw(&mut self, want: u16) -> Option<Vec<u8>> {
        let start = self.pos;
        let (ty, _) = self.tlv()?;
        (ty == want).then(|| self.d[start..self.pos].to_vec())
    }
    fn address(&mut self) -> Option<Address> {
        Some(Address { ty: self.u32()?, mode: self.u32()?, addr: self.raw_string()? })
    }
    fn done(&self) -> bool {
        self.pos == self.d.len()
    }
}

/// RsMsgItem body; `config` = with the message id (config file)
fn parse_msg(r: &mut Reader, config: bool) -> Option<MsgItem> {
    Some(MsgItem {
        flags: r.u32()?,
        send_time: r.u32()?,
        recv_time: r.u32()?,
        subject: r.tlv_string(TLV_STR_SUBJECT)?,
        message: r.tlv_string(TLV_STR_MSG)?,
        peers_to: r.tlv_ids(TLV_PEERSET)?,
        peers_cc: r.tlv_ids(TLV_PEERSET)?,
        peers_bcc: r.tlv_ids(TLV_PEERSET)?,
        gxs_to: r.tlv_ids(TLV_GXSIDSET)?,
        gxs_cc: r.tlv_ids(TLV_GXSIDSET)?,
        gxs_bcc: r.tlv_ids(TLV_GXSIDSET)?,
        attachment: r.tlv_raw(TLV_FILESET)?,
        msg_id: if config { r.u32()? } else { 0 },
    })
}

/// An `RsMsgItem` received from a friend (payload after the 8 byte header).
pub fn parse_wire_msg(payload: &[u8]) -> Option<MsgItem> {
    let mut r = Reader { d: payload, pos: 0 };
    let m = parse_msg(&mut r, false)?;
    Some(m)
}

fn parse_mail(body: &[u8]) -> Option<Mail> {
    let mut r = Reader { d: body, pos: 0 };
    let from = r.address()?;
    let to = r.address()?;
    let n = r.u32()? as usize;
    let mut tags = BTreeSet::new();
    for _ in 0..n.min(10_000) {
        tags.insert(r.u32()?);
    }
    let parent_id = r.u32()?;
    let msg = parse_msg(&mut r, true)?;
    r.done().then_some(Mail { from, to, tags, parent_id, msg })
}

fn parse_out_info(r: &mut Reader) -> Option<OutInfo> {
    Some(OutInfo { origin: r.address()?, destination: r.address()?, flags: r.u32()?, grouter_id: r.u64()? })
}

fn parse_outgoing(body: &[u8]) -> Option<BTreeMap<u32, BTreeMap<u32, OutInfo>>> {
    let mut r = Reader { d: body, pos: 0 };
    let mut out = BTreeMap::new();
    let n = r.u32()?;
    for _ in 0..n {
        let id = r.u32()?;
        let m = r.u32()?;
        let mut copies = BTreeMap::new();
        for _ in 0..m {
            let sub = r.u32()?;
            copies.insert(sub, parse_out_info(&mut r)?);
        }
        out.insert(id, copies);
    }
    r.done().then_some(out)
}

fn parse_tag(body: &[u8]) -> Option<(u32, String, u32)> {
    let mut r = Reader { d: body, pos: 0 };
    let text = r.tlv_string(TLV_STR_NAME)?;
    let color = r.u32()?;
    let id = r.u32()?;
    r.done().then_some((id, text, color))
}

// --- writing ---------------------------------------------------------------------

fn tlv(out: &mut Vec<u8>, ty: u16, value: &[u8]) {
    out.extend(ty.to_be_bytes());
    out.extend(((value.len() + 6) as u32).to_be_bytes());
    out.extend(value);
}

fn ids(out: &mut Vec<u8>, ty: u16, ids: &[[u8; 16]]) {
    let flat: Vec<u8> = ids.iter().flatten().copied().collect();
    tlv(out, ty, &flat);
}

fn address(out: &mut Vec<u8>, a: &Address) {
    out.extend(a.ty.to_be_bytes());
    out.extend(a.mode.to_be_bytes());
    out.extend((a.addr.len() as u32).to_be_bytes());
    out.extend(a.addr.as_bytes());
}

pub fn write_msg(out: &mut Vec<u8>, m: &MsgItem, config: bool) {
    out.extend(m.flags.to_be_bytes());
    out.extend(m.send_time.to_be_bytes());
    out.extend(m.recv_time.to_be_bytes());
    tlv(out, TLV_STR_SUBJECT, m.subject.as_bytes());
    tlv(out, TLV_STR_MSG, m.message.as_bytes());
    ids(out, TLV_PEERSET, &m.peers_to);
    ids(out, TLV_PEERSET, &m.peers_cc);
    ids(out, TLV_PEERSET, &m.peers_bcc);
    ids(out, TLV_GXSIDSET, &m.gxs_to);
    ids(out, TLV_GXSIDSET, &m.gxs_cc);
    ids(out, TLV_GXSIDSET, &m.gxs_bcc);
    if m.attachment.len() >= 6 {
        out.extend(&m.attachment);
    } else {
        tlv(out, TLV_FILESET, &[]);
    }
    if config {
        out.extend(m.msg_id.to_be_bytes());
    }
}

fn mail_body(m: &Mail) -> Vec<u8> {
    let mut out = vec![];
    address(&mut out, &m.from);
    address(&mut out, &m.to);
    out.extend((m.tags.len() as u32).to_be_bytes());
    for t in &m.tags {
        out.extend(t.to_be_bytes());
    }
    out.extend(m.parent_id.to_be_bytes());
    write_msg(&mut out, &m.msg, true);
    out
}

fn outgoing_body(o: &BTreeMap<u32, BTreeMap<u32, OutInfo>>) -> Vec<u8> {
    let mut out = (o.len() as u32).to_be_bytes().to_vec();
    for (id, copies) in o {
        out.extend(id.to_be_bytes());
        out.extend((copies.len() as u32).to_be_bytes());
        for (sub, info) in copies {
            out.extend(sub.to_be_bytes());
            address(&mut out, &info.origin);
            address(&mut out, &info.destination);
            out.extend(info.flags.to_be_bytes());
            out.extend(info.grouter_id.to_be_bytes());
        }
    }
    out
}

fn tag_body(id: u32, text: &str, color: u32) -> Vec<u8> {
    let mut out = vec![];
    tlv(&mut out, TLV_STR_NAME, text.as_bytes());
    out.extend(color.to_be_bytes());
    out.extend(id.to_be_bytes());
    out
}

/// item header (version, service, sub type, size)
pub fn item(sub_type: u8, body: Vec<u8>) -> Vec<u8> {
    let mut out = ITEM_PREFIX.to_vec();
    out.push(sub_type);
    out.extend(((body.len() + HEADER_SIZE) as u32).to_be_bytes());
    out.extend(body);
    out
}

// --- the store -------------------------------------------------------------------

pub struct MailStore {
    path: PathBuf,
    keys: SslKey,
    /// writing to RetroShare's msgs.cfg is safe
    shared_file: bool,
    pub mails: BTreeMap<u32, Mail>,
    pub outgoing: BTreeMap<u32, BTreeMap<u32, OutInfo>>,
    pub tags: BTreeMap<u32, (String, u32)>,
    other_items: Vec<Vec<u8>>,
    used_ids: BTreeSet<u32>,
}

/// RS_MSGTAGTYPE_* standard tags (p3MsgService::getStandardTagTypes)
const STANDARD_TAGS: [(u32, &str, u32); 5] = [
    (1, "Important", 0xFF0000),
    (2, "Work", 0xFF9900),
    (3, "Personal", 0x009900),
    (4, "Todo", 0x3333FF),
    (5, "Later", 0x993399),
];

impl MailStore {
    fn load(config_dir: PathBuf, keys: &SslKey) -> Self {
        let mut store = MailStore {
            path: config_dir.join(FILE),
            keys: keys.clone(),
            shared_file: true,
            mails: BTreeMap::new(),
            outgoing: BTreeMap::new(),
            tags: BTreeMap::new(),
            other_items: vec![],
            used_ids: BTreeSet::new(),
        };
        if store.path.exists() {
            match config_store::load_file(&store.path, keys) {
                Ok(data) => {
                    if let Err(why) = store.parse(&data) {
                        warn!("[mail] {FILE}: {why}; rustyshare keeps its mail in {FALLBACK_FILE} and does not change {FILE}");
                        store.shared_file = false;
                    }
                }
                Err(err) => {
                    warn!("[mail] can't load {FILE}: {err}; using {FALLBACK_FILE}");
                    store.shared_file = false;
                }
            }
        }
        if !store.shared_file {
            // RetroShare's mail is shown, ours is stored separately
            store.other_items.clear();
            store.path = config_dir.join(FALLBACK_FILE);
            if store.path.exists() {
                match config_store::load_file(&store.path, keys) {
                    Ok(data) => {
                        if let Err(why) = store.parse(&data) {
                            warn!("[mail] {FALLBACK_FILE}: {why}");
                        }
                    }
                    Err(err) => warn!("[mail] can't load {FALLBACK_FILE}: {err}"),
                }
            }
        }
        for (id, text, color) in STANDARD_TAGS {
            store.tags.entry(id).or_insert((text.to_owned(), color));
        }
        info!(
            "[mail] {} mails, {} waiting in the outbox ({})",
            store.mails.len(),
            store.outgoing.values().map(|c| c.len()).sum::<usize>(),
            store.path.display()
        );
        store
    }

    /// Reads all items; Err (with the reason) when writing the file back could lose or
    /// change anything.
    fn parse(&mut self, data: &[u8]) -> Result<(), String> {
        let mut problem = None;
        let mut pos = 0;
        while pos + HEADER_SIZE <= data.len() {
            let size = NetworkEndian::read_u32(&data[pos + 4..pos + 8]) as usize;
            if size < HEADER_SIZE || pos + size > data.len() {
                return Err(format!("broken item at offset {pos}"));
            }
            let mut raw_item = data[pos..pos + size].to_vec();
            pos += size;
            // rustyshare 0.2 first wrote mail items with service 0x0022: read as 0x0013
            if raw_item[0..3] == [0x02, 0x00, 0x22] && matches!(raw_item[3], SUBTYPE_MAIL_STORAGE | SUBTYPE_OUTGOING_MAP | SUBTYPE_TAG_TYPE) {
                raw_item[2] = ITEM_PREFIX[2];
            }
            let raw = raw_item.as_slice();
            let body = &raw[HEADER_SIZE..];
            if raw[0..3] != ITEM_PREFIX {
                self.other_items.push(raw.to_vec());
                continue;
            }
            let sub = raw[3];
            let ok = match sub {
                SUBTYPE_MAIL_STORAGE => match parse_mail(body) {
                    Some(m) if item(sub, mail_body(&m)) == raw => {
                        self.used_ids.insert(m.msg.msg_id);
                        self.mails.insert(m.msg.msg_id, m);
                        true
                    }
                    _ => false,
                },
                SUBTYPE_OUTGOING_MAP => match parse_outgoing(body) {
                    Some(o) if item(sub, outgoing_body(&o)) == raw => {
                        for (id, copies) in o {
                            self.used_ids.insert(id);
                            self.used_ids.extend(copies.keys());
                            self.outgoing.entry(id).or_default().extend(copies);
                        }
                        true
                    }
                    _ => false,
                },
                SUBTYPE_TAG_TYPE => match parse_tag(body) {
                    Some((id, text, color)) if item(sub, tag_body(id, &text, color)) == raw => {
                        self.tags.insert(id, (text, color));
                        true
                    }
                    _ => false,
                },
                s if OLD_SUBTYPES.contains(&s) => {
                    problem.get_or_insert_with(|| "mail in RetroShare's old format (start RetroShare once to convert it)".to_string());
                    self.other_items.push(raw.to_vec());
                    continue;
                }
                _ => {
                    self.other_items.push(raw.to_vec());
                    continue;
                }
            };
            if !ok {
                problem.get_or_insert_with(|| format!("item type {sub:#04x} at offset {} not understood exactly", pos - size));
                self.other_items.push(raw.to_vec());
            }
        }
        match problem {
            Some(p) => Err(p),
            None => Ok(()),
        }
    }

    pub fn save(&self) {
        let mut data = vec![];
        for m in self.mails.values() {
            data.extend(item(SUBTYPE_MAIL_STORAGE, mail_body(m)));
        }
        data.extend(item(SUBTYPE_OUTGOING_MAP, outgoing_body(&self.outgoing)));
        for (id, (text, color)) in &self.tags {
            data.extend(item(SUBTYPE_TAG_TYPE, tag_body(*id, text, *color)));
        }
        for raw in &self.other_items {
            data.extend(raw);
        }
        match config_store::save_file(&self.path, &data, &self.keys) {
            Ok(()) => log::debug!("[mail] saved {}", self.path.display()),
            Err(err) => warn!("[mail] can't save {}: {err}", self.path.display()),
        }
    }

    /// A new message id (random, unused; p3MsgService::getNewUniqueMsgId()).
    pub fn new_id(&mut self) -> u32 {
        use nanorand::Rng;
        let mut rng = nanorand::WyRand::new();
        loop {
            let id: u32 = rng.generate();
            if id != 0 && self.used_ids.insert(id) {
                return id;
            }
        }
    }
}

static STORE: OnceLock<Mutex<MailStore>> = OnceLock::new();
static OUTBOX: OnceLock<Notify> = OnceLock::new();

pub fn load(config_dir: PathBuf, keys: &SslKey) {
    let _ = STORE.set(Mutex::new(MailStore::load(config_dir, keys)));
}

/// The mail store (None before `load`).
pub fn store() -> Option<std::sync::MutexGuard<'static, MailStore>> {
    STORE.get().map(|m| m.lock().expect("lock poisoned"))
}

/// Wakes the mail service to send what is in the outbox.
pub fn outbox_changed() {
    OUTBOX.get_or_init(Notify::new).notify_one();
}

pub async fn outbox_wait() {
    OUTBOX.get_or_init(Notify::new).notified().await
}

/// Which box a stored mail is in, like p3MsgService's lists.
pub fn box_of(m: &Mail) -> u8 {
    let f = m.msg.flags;
    if f & flags::TRASH != 0 {
        5
    } else if f & flags::DRAFT != 0 {
        3
    } else if f & flags::OUTGOING != 0 {
        4
    } else {
        1
    }
}
