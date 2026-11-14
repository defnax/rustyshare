//! GXS tunnels and distant chat, like libretroshare's `gxstunnel/p3gxstunnel.cc` and
//! `chat/distantchat.cc`.
//!
//! A GXS tunnel is an encrypted connection between two GXS identities through turtle
//! tunnels (see `turtle.rs`, which owns this and calls it):
//! - the client digs turtle tunnels for a "hash" made of 4 random bytes and the
//!   destination identity (16 bytes); whoever owns that identity answers
//! - both ends send a signed Diffie-Hellman public key (2048 bit, g = 5) in clear
//!   (turtle data starting with 8 zero bytes); the AES key is SHA1(DH secret)[0..16]
//! - everything else is encrypted: IV (8) | HMAC-SHA1 (20) | AES-256-CBC, key and IV
//!   from `EVP_BytesToKey(sha1, salt = IV, 5 rounds)` (RsAES::aes_crypt_8_16)
//! - data items are acknowledged and sent again every 10 s until they are
//! - keep alive every 6 s; the tunnel id is SHA1(smaller id | bigger id)[0..16]
//!
//! Distant chat is a client of the tunnels (service id 0xa0001): normal chat items
//! (RsChatMsgItem, RsChatStatusItem) go through the tunnel.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use log::{debug, info, warn};
use openssl::{
    bn::BigNum,
    dh::Dh,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    sign::{Signer, Verifier},
    symm::Cipher,
};
use retroshare_compat::{
    basics::{DistantChatPeerId, GxsId},
    events::{ChatMessage, EventType},
    serde::{from_retroshare_wire_result, to_retroshare_wire},
    services::chat::ChatId,
    tlv::{
        tlv_keys::{KeyId, TlvKeySignature, TlvKeySignatureInner, TlvPublicRSAKey},
        Tlv,
    },
};
use serde::{Deserialize, Serialize};
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};

use crate::{
    history::{HistoryChat, HistoryEntry},
    model::{intercom::Intercom, DataCore},
};

/// RS_SERVICE_TYPE_GXS_TUNNEL
const SERVICE: [u8; 2] = [0x00, 0x28];
const SUB_DATA: u8 = 0x01;
const SUB_DH_PUBLIC_KEY: u8 = 0x02;
const SUB_STATUS: u8 = 0x03;
const SUB_DATA_ACK: u8 = 0x04;

const FLAG_CLOSING: u32 = 0x0400;
const FLAG_ACK_CONNECTION: u32 = 0x0800;
const FLAG_KEEP_ALIVE: u32 = 0x1000;

const KEEP_ALIVE_TIMEOUT: u64 = 6;
const RESEND_DELAY: u64 = 10;
const DH_RESTART_MIN_DELAY: u64 = 10;
const DATA_PRINT_STORAGE: u64 = 600;

/// DistantChatService: DISTANT_CHAT_GXS_TUNNEL_SERVICE_ID
pub const DISTANT_CHAT_SERVICE: u32 = 0xa0001;
/// RsChatSerialiser items (service 0x0012)
const CHAT_SUB_MSG: u8 = 0x01;
const CHAT_SUB_STATUS: u8 = 0x04;
const CHAT_FLAG_PRIVATE: u32 = 0x0001;
const CHAT_FLAG_PARTIAL: u32 = 0x0100;
const CHAT_FLAG_CLOSING: u32 = 0x0400;
const CHAT_FLAG_KEEP_ALIVE: u32 = 0x1000;
const CHAT_FLAG_REFUSED: u32 = 0x2000;
/// p3ChatService: long messages are split (MAX_MESSAGE_SECURITY_SIZE is 31000)
const CHAT_MAX_PART: usize = 8000;

const SAVE_FILE: &str = "rustyshare_distant_chats.json";

const DH_PRIME_2048: &str = "B3B86A844550486C7EA459FA468D3A8EFD71139593FE1C658BBEFA9B2FC0AD2628242C2CDC2F91F5B220ED29AAC271192A7374DFA28CDDCA70252F342D0821273940344A7A6A3CB70C7897A39864309F6CAC5C7EA18020EF882693CA2C12BB211B7BA8367D5A7C7252A5B5E840C9E8F081469EBA0B98BCC3F593A4D9C4D5DF539362084F1B9581316C1F80FDAD452FD56DBC6B8ED0775F596F7BB22A3FE2B4753764221528D33DB4140DE58083DB660E3E105123FC963BFF108AC3A268B7380FFA72005A1515C371287C5706FFA6062C9AC73A9B1A6AC842C2764CDACFC85556607E86611FDF486C222E4896CDF6908F239E177ACC641FCBFF72A758D1C10CBB";

pub type Hash = [u8; 20];
pub type Vpid = [u8; 16];
pub type TunnelId = [u8; 16];

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

// --- what the turtle router has to do for us ------------------------------------------

#[derive(Debug)]
pub enum TurtleAction {
    /// turtle generic data (or "fast" data) into the tunnel of a virtual peer
    Send { vpid: Vpid, data: Vec<u8>, fast: bool },
    /// dig tunnels for this hash until stopped (p3turtle::monitorTunnels)
    Monitor(Hash),
    StopMonitor(Hash),
    /// dig again now (p3turtle::forceReDiggTunnels)
    Redigg(Hash),
    /// stop digging, existing tunnels stay until idle (p3turtle::stopMonitoringTunnels)
    StopDigging(Hash),
}

// --- commands from the web interface ---------------------------------------------------

pub enum TunnelCmd {
    /// initiateDistantChatConnexion(to, from): the distant chat id
    OpenChat { to: GxsId, from: GxsId, reply: oneshot::Sender<Result<String, String>> },
    SendChat { tunnel: TunnelId, text: String, reply: oneshot::Sender<Result<(), String>> },
    CloseChat { tunnel: TunnelId, reply: oneshot::Sender<bool> },
    /// closes a chat and removes it from the list
    Forget(TunnelId),
    /// accept distant chats from: 0 everybody, 1 contacts only, 2 nobody
    SetPermission(u32),
}

static CMD: OnceLock<UnboundedSender<TunnelCmd>> = OnceLock::new();

pub fn set_cmd_sender(tx: UnboundedSender<TunnelCmd>) {
    let _ = CMD.set(tx);
}

/// Sends a command to the tunnel service (false: it isn't running).
pub fn command(cmd: TunnelCmd) -> bool {
    CMD.get().map(|tx| tx.send(cmd).is_ok()).unwrap_or(false)
}

/// Distant chats as shown in the web interface.
#[derive(Serialize, Clone, Debug)]
pub struct DistantChatInfo {
    /// distant chat id = tunnel id (hex)
    pub id: String,
    pub own_id: String,
    pub to_id: String,
    pub to_name: String,
    /// like RS_DISTANT_CHAT_STATUS_*: 0 unknown, 1 tunnel down (connecting),
    /// 2 can talk, 3 closed by the other side
    pub status: u32,
    /// messages not yet acknowledged
    pub pending: usize,
    /// we opened it (client side)
    pub own_initiative: bool,
}

static CHATS: RwLock<Vec<DistantChatInfo>> = RwLock::new(Vec::new());
static PERMISSION: Mutex<u32> = Mutex::new(0);

pub fn distant_chats() -> Vec<DistantChatInfo> {
    CHATS.read().map(|c| c.clone()).unwrap_or_default()
}

pub fn permission() -> u32 {
    PERMISSION.lock().map(|p| *p).unwrap_or(0)
}

// --- state -------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    TunnelDn,
    CanTalk,
    RemotelyClosed,
}

struct Contact {
    status: Status,
    own_id: GxsId,
    to_id: GxsId,
    hash: Hash,
    /// we dug the tunnel (DIRECTION_SERVER in RetroShare's words)
    client: bool,
    vpid: Option<Vpid>,
    aes_key: [u8; 16],
    last_contact: u64,
    last_keep_alive: u64,
    received_prints: HashMap<u64, u64>,
    accepts_fast: bool,
    probed_fast: bool,
}

#[derive(PartialEq, Eq)]
enum DhStatus {
    Uninitialized,
    HalfKeyDone,
    KeyAvailable,
}

struct DhInfo {
    dh: Option<Dh<Private>>,
    status: DhStatus,
    own_id: GxsId,
    client: bool,
    hash: Hash,
    tunnel_id: Option<TunnelId>,
    last_restart: u64,
}

struct PendingData {
    tunnel: TunnelId,
    item: Vec<u8>,
    last_try: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct SavedChat {
    id: String,
    own_id: String,
    to_id: String,
    own_initiative: bool,
}
#[derive(Serialize, Deserialize, Default)]
struct SavedChats {
    #[serde(default)]
    permission: u32,
    #[serde(default)]
    chats: Vec<SavedChat>,
}

pub struct GxsTunnels {
    core: Arc<DataCore>,
    core_tx: UnboundedSender<Intercom>,
    /// own identities, refreshed in the background (tunnel requests are answered at once)
    own_ids: Arc<RwLock<HashSet<GxsId>>>,
    contacts: HashMap<TunnelId, Contact>,
    vpeers: HashMap<Vpid, DhInfo>,
    /// items without acknowledgement (acks, status): sent when the tunnel can talk
    pending_items: Vec<(TunnelId, Vec<u8>)>,
    pending_data: BTreeMap<u64, PendingData>,
    counter: u64,
    actions: Vec<TurtleAction>,
    /// distant chats: parts of long messages, names, known chats
    partial: HashMap<TunnelId, String>,
    names: HashMap<GxsId, String>,
    saved: HashMap<TunnelId, SavedChat>,
    save_file: PathBuf,
    permission: u32,
}

impl GxsTunnels {
    pub async fn new(core: &Arc<DataCore>, core_tx: UnboundedSender<Intercom>) -> (Self, UnboundedReceiver<TunnelCmd>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        set_cmd_sender(tx);

        let save_file = core.get_config_dir().await.join(SAVE_FILE);
        let loaded: SavedChats = std::fs::read(&save_file)
            .ok()
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default();
        let saved: HashMap<TunnelId, SavedChat> = loaded
            .chats
            .into_iter()
            .filter_map(|c| Some((hex::decode(&c.id).ok()?.try_into().ok()?, c)))
            .collect();
        if let Ok(mut p) = PERMISSION.lock() {
            *p = loaded.permission;
        }

        // own identities, for answering tunnel requests without waiting
        let own_ids = Arc::new(RwLock::new(HashSet::new()));
        {
            let own_ids = own_ids.clone();
            let core = core.clone();
            tokio::spawn(async move {
                loop {
                    let ids: HashSet<GxsId> = core
                        .get_service_data()
                        .gxs_id()
                        .get_group_meta_all()
                        .await
                        .into_iter()
                        .filter(|g| g.subscribe_flags.contains(retroshare_compat::gxs::sqlite::types::SubscribeFlags::ADMIN))
                        .map(|g| g.group_id.into())
                        .collect();
                    if !ids.is_empty() {
                        if let Ok(mut o) = own_ids.write() {
                            *o = ids;
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            });
        }

        let me = GxsTunnels {
            core: core.clone(),
            core_tx,
            own_ids,
            contacts: HashMap::new(),
            vpeers: HashMap::new(),
            pending_items: vec![],
            pending_data: BTreeMap::new(),
            counter: 1,
            actions: vec![],
            partial: HashMap::new(),
            names: HashMap::new(),
            saved,
            save_file,
            permission: loaded.permission,
        };
        me.publish_state();
        (me, rx)
    }

    /// our own identities (kept up to date in the background)
    pub fn own_ids(&self) -> Arc<RwLock<HashSet<GxsId>>> {
        self.own_ids.clone()
    }

    pub fn take_actions(&mut self) -> Vec<TurtleAction> {
        std::mem::take(&mut self.actions)
    }

    fn is_own(&self, id: &GxsId) -> bool {
        self.own_ids.read().map(|o| o.contains(id)).unwrap_or(false)
    }

    // --- called by the turtle router --------------------------------------------------

    /// p3GxsTunnelService::handleTunnelRequest(): is the destination one of our ids?
    pub fn handle_tunnel_request(&self, hash: &Hash) -> bool {
        self.is_own(&destination_from_hash(hash))
    }

    /// p3GxsTunnelService::addVirtualPeer(): a turtle tunnel is there, start the key
    /// exchange. `client`: we dug it.
    pub async fn add_virtual_peer(&mut self, hash: Hash, vpid: Vpid, client: bool) {
        let own_id = if client {
            match self.contacts.values().find(|c| c.hash == hash) {
                None => return debug!("[gxs tunnel] no contact for the new tunnel, dropping it"),
                Some(c) if c.status == Status::CanTalk => return, // we already have one
                Some(c) => c.own_id,
            }
        } else {
            destination_from_hash(&hash)
        };
        self.vpeers.insert(
            vpid,
            DhInfo {
                dh: None,
                status: DhStatus::Uninitialized,
                own_id,
                client,
                hash,
                tunnel_id: None,
                last_restart: 0,
            },
        );
        self.restart_dh(vpid, own_id).await;
    }

    /// p3GxsTunnelService::removeVirtualPeer()
    pub fn remove_virtual_peer(&mut self, vpid: &Vpid) {
        let Some(info) = self.vpeers.remove(vpid) else { return };
        let Some(tunnel) = info.tunnel_id else { return };
        if let Some(c) = self.contacts.get_mut(&tunnel) {
            if c.vpid.as_ref() == Some(vpid) {
                c.status = Status::TunnelDn;
                c.vpid = None;
                self.publish_state();
            }
        }
    }

    /// p3GxsTunnelService::receiveTurtleData()
    pub async fn receive_turtle_data(&mut self, vpid: Vpid, data: &[u8], fast: bool) {
        if data.len() < 8 {
            return;
        }
        if data[..8] != [0u8; 8] {
            self.handle_encrypted(vpid, data, fast).await;
            return;
        }
        // clear text: only the DH public key
        let item = &data[8..];
        if item.len() < 8 || item[1..3] != SERVICE || item[3] != SUB_DH_PUBLIC_KEY {
            return debug!("[gxs tunnel] unexpected clear item");
        }
        self.handle_dh_public_key(vpid, &item[8..]).await;
    }

    // --- key exchange ---------------------------------------------------------------------

    async fn restart_dh(&mut self, vpid: Vpid, own_id: GxsId) {
        let dh = match new_dh() {
            Ok(dh) => dh,
            Err(e) => return warn!("[gxs tunnel] can't make a DH key: {e}"),
        };
        let public = dh.public_key().to_vec();
        if let Some(info) = self.vpeers.get_mut(&vpid) {
            info.own_id = own_id;
            info.last_restart = now();
            info.dh = Some(dh);
            info.status = DhStatus::HalfKeyDone;
        }
        // locked_sendDHPublicKey(): the key, signed by our identity, with our public key
        let ids = self.core.get_service_data().gxs_id();
        let (Some(private), Some(pub_key)) = (ids.get_priv_keys_by_id(&own_id).await, ids.get_pub_keys_by_id(&own_id).await) else {
            return warn!("[gxs tunnel] no keys for own identity {own_id}");
        };
        let signature = match Rsa::private_key_from_der(private.key_data.as_slice())
            .map_err(|e| e.to_string())
            .and_then(|rsa| rsa_sha1_sign(&rsa, &public))
        {
            Ok(s) => s,
            Err(e) => return warn!("[gxs tunnel] signing the DH key failed: {e}"),
        };
        let sig: TlvKeySignature = Tlv(TlvKeySignatureInner { key_id: KeyId::from(own_id), sign_data: signature.into() });
        let mut body = (public.len() as u32).to_be_bytes().to_vec();
        body.extend(&public);
        body.extend(to_retroshare_wire(&sig));
        body.extend(to_retroshare_wire(&pub_key));
        let mut data = vec![0u8; 8];
        data.extend(item(SUB_DH_PUBLIC_KEY, &body));
        debug!("[gxs tunnel] sending DH key to virtual peer {}", hex::encode(vpid));
        self.actions.push(TurtleAction::Send { vpid, data, fast: false });
    }

    /// p3GxsTunnelService::handleRecvDHPublicKey()
    async fn handle_dh_public_key(&mut self, vpid: Vpid, body: &[u8]) {
        if !self.vpeers.contains_key(&vpid) {
            return debug!("[gxs tunnel] DH key from an unknown virtual peer");
        }
        // BIGNUM (u32 length + bytes), RsTlvKeySignature, RsTlvPublicRSAKey
        let Some(len) = body.get(..4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize) else { return };
        let Some(public) = body.get(4..4 + len).map(|b| b.to_vec()) else { return };
        let rest = &body[4 + len..];
        let Some((sig, rest)) = take_tlv(rest) else { return warn!("[gxs tunnel] broken DH item") };
        let Some((key, _)) = take_tlv(rest) else { return warn!("[gxs tunnel] broken DH item") };
        let parsed = std::panic::catch_unwind(|| {
            let sig: Result<TlvKeySignature, _> = from_retroshare_wire_result(&mut sig.to_vec());
            let key: Result<TlvPublicRSAKey, _> = from_retroshare_wire_result(&mut key.to_vec());
            (sig.ok(), key.ok())
        });
        let Ok((Some(sig), key)) = parsed else { return warn!("[gxs tunnel] can't read the DH signature") };
        let sender: GxsId = sig.key_id.to_owned().into();
        let sig_data = sig.sign_data.to_vec();

        // the signer's key: known identity, or the key sent along when it checks out
        let known = self.core.get_service_data().gxs_id().get_pub_keys_by_id(&sender).await;
        let signer_key = match known {
            Some(k) => k,
            None => match key {
                Some(k) if GxsId::from(k.key_id.to_owned()) == sender && check_public_key(&k) => k,
                _ => return warn!("[gxs tunnel] unknown identity {sender} and no usable key in the DH item"),
            },
        };
        match rsa_sha1_verify(&signer_key, &public, &sig_data) {
            Ok(true) => {}
            _ => return warn!("[gxs tunnel] wrong signature on the DH key of {sender}"),
        }

        let Some(info) = self.vpeers.get(&vpid) else { return };
        if info.dh.is_none() {
            return;
        }
        if info.status == DhStatus::KeyAvailable {
            // the other side restarted: so do we
            let own = info.own_id;
            self.restart_dh(vpid, own).await;
        }
        let Some(info) = self.vpeers.get_mut(&vpid) else { return };
        let own_id = info.own_id;
        let tunnel_id = make_tunnel_id(&own_id, &sender);
        info.tunnel_id = Some(tunnel_id);
        let (client, hash) = (info.client, info.hash);

        // a working tunnel through another virtual peer stays
        if let Some(c) = self.contacts.get(&tunnel_id) {
            if c.status == Status::CanTalk {
                if let Some(other) = c.vpid {
                    if other != vpid && self.vpeers.contains_key(&other) {
                        return;
                    }
                }
            }
        }
        let Some(info) = self.vpeers.get_mut(&vpid) else { return };
        let Some(dh) = info.dh.as_ref() else { return };
        let secret = match BigNum::from_slice(&public).and_then(|p| dh.compute_key(&p)) {
            Ok(s) => s,
            Err(e) => return warn!("[gxs tunnel] DH failed: {e}"),
        };
        // RetroShare uses DH_compute_key() and requires the full size
        if secret.len() != 256 {
            return warn!("[gxs tunnel] DH secret too short, waiting for a new key exchange");
        }
        info.status = DhStatus::KeyAvailable;
        let mut aes_key = [0u8; 16];
        aes_key.copy_from_slice(&openssl::sha::sha1(&secret)[..16]);

        let t = now();
        let c = self.contacts.entry(tunnel_id).or_insert_with(|| Contact {
            status: Status::TunnelDn,
            own_id,
            to_id: sender,
            hash,
            client,
            vpid: None,
            aes_key,
            last_contact: t,
            last_keep_alive: t,
            received_prints: HashMap::new(),
            accepts_fast: false,
            probed_fast: false,
        });
        c.aes_key = aes_key;
        c.last_contact = t;
        c.last_keep_alive = t;
        c.status = Status::CanTalk;
        c.vpid = Some(vpid);
        c.client = client;
        c.own_id = own_id;
        c.to_id = sender;
        info!("[gxs tunnel] tunnel {} with {sender} can talk", hex::encode(tunnel_id));
        self.pending_items.push((tunnel_id, item(SUB_STATUS, &FLAG_ACK_CONNECTION.to_be_bytes())));
        self.remember_chat(tunnel_id);
        self.flush();
        self.publish_state();
    }

    // --- encrypted traffic ----------------------------------------------------------------

    /// p3GxsTunnelService::handleEncryptedData()
    async fn handle_encrypted(&mut self, vpid: Vpid, data: &[u8], fast: bool) {
        if data.len() < 28 + 16 {
            return;
        }
        let Some(info) = self.vpeers.get(&vpid) else { return };
        let Some(tunnel_id) = info.tunnel_id else { return debug!("[gxs tunnel] encrypted data before the key exchange") };
        let (last_restart, half, own) = (info.last_restart, info.status == DhStatus::HalfKeyDone, info.own_id);
        let Some(c) = self.contacts.get_mut(&tunnel_id) else { return };
        if fast {
            c.accepts_fast = true;
        }
        if c.status == Status::CanTalk && c.vpid != Some(vpid) {
            return; // a packet of an old tunnel
        }
        let (iv, mac, encrypted) = (&data[..8], &data[8..28], &data[28..]);
        let clear = match hmac_sha1(&c.aes_key, encrypted) {
            Ok(m) if m.as_slice() == mac => aes_decrypt(&c.aes_key, iv, encrypted).ok(),
            _ => None,
        };
        let Some(clear) = clear else {
            // rejectPacket(): new key exchange, but not too often
            if !half && now() >= last_restart + DH_RESTART_MIN_DELAY {
                debug!("[gxs tunnel] bad packet, restarting the key exchange");
                self.restart_dh(vpid, own).await;
            }
            return;
        };
        c.status = Status::CanTalk;
        c.last_contact = now();
        if clear.len() < 8 || clear[1..3] != SERVICE {
            return;
        }
        let body = &clear[8..];
        match clear[3] {
            SUB_DATA => self.handle_data(tunnel_id, body).await,
            SUB_DATA_ACK => {
                if let Some(counter) = body.get(..8).map(|b| u64::from_be_bytes(b.try_into().unwrap_or_default())) {
                    self.pending_data.remove(&counter);
                    self.publish_state();
                }
            }
            SUB_STATUS => {
                let status = body.get(..4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0);
                if status == FLAG_CLOSING {
                    if let Some(c) = self.contacts.get_mut(&tunnel_id) {
                        c.status = if c.client { Status::TunnelDn } else { Status::RemotelyClosed };
                    }
                    info!("[gxs tunnel] tunnel {} closed by the other side", hex::encode(tunnel_id));
                    self.publish_state();
                } else if status == FLAG_ACK_CONNECTION {
                    self.publish_state();
                } else if status != FLAG_KEEP_ALIVE {
                    debug!("[gxs tunnel] unknown status {status:#x}");
                }
            }
            sub => debug!("[gxs tunnel] unknown item {sub:#x}"),
        }
    }

    /// p3GxsTunnelService::handleRecvTunnelDataItem()
    async fn handle_data(&mut self, tunnel_id: TunnelId, body: &[u8]) {
        // u64 counter, u32 flags, u32 service id, u32 size + data
        if body.len() < 20 {
            return;
        }
        let counter = u64::from_be_bytes(body[..8].try_into().unwrap_or_default());
        let service = u32::from_be_bytes([body[12], body[13], body[14], body[15]]);
        let size = u32::from_be_bytes([body[16], body[17], body[18], body[19]]) as usize;
        let Some(payload) = body.get(20..20 + size) else { return };

        // acknowledged in any case (an item without ack, to avoid loops)
        self.pending_items.push((tunnel_id, item(SUB_DATA_ACK, &counter.to_be_bytes())));
        if service != DISTANT_CHAT_SERVICE {
            return debug!("[gxs tunnel] data for unknown client service {service:#x}");
        }
        let Some(c) = self.contacts.get_mut(&tunnel_id) else { return };
        if c.received_prints.contains_key(&counter) {
            return; // sent again, we have it already
        }
        c.received_prints.insert(counter, now());
        let (from, client) = (c.to_id, c.client);
        let payload = payload.to_vec();
        self.distant_chat_receive(tunnel_id, from, client, &payload).await;
        self.flush();
    }

    /// Queues data for a client service (p3GxsTunnelService::sendData()).
    fn send_data(&mut self, tunnel: TunnelId, service: u32, data: &[u8]) {
        let counter = self.counter;
        self.counter += 1;
        let mut body = counter.to_be_bytes().to_vec();
        body.extend(0u32.to_be_bytes()); // flags
        body.extend(service.to_be_bytes());
        body.extend((data.len() as u32).to_be_bytes());
        body.extend(data);
        self.pending_data.insert(counter, PendingData { tunnel, item: item(SUB_DATA, &body), last_try: 0 });
    }

    /// locked_sendEncryptedTunnelData(): false when the tunnel can't talk now.
    fn send_encrypted(&mut self, tunnel: &TunnelId, clear: &[u8]) -> bool {
        let Some(c) = self.contacts.get_mut(tunnel) else { return false };
        if c.status != Status::CanTalk {
            return false;
        }
        let Some(vpid) = c.vpid else { return false };
        let mut iv = [0u8; 8];
        while iv == [0u8; 8] {
            if openssl::rand::rand_bytes(&mut iv).is_err() {
                return false;
            }
        }
        let Ok(encrypted) = aes_encrypt(&c.aes_key, &iv, clear) else { return false };
        let Ok(mac) = hmac_sha1(&c.aes_key, &encrypted) else { return false };
        let mut data = iv.to_vec();
        data.extend(mac);
        data.extend(encrypted);
        // like RetroShare: normal data until the other side showed it takes "fast" items,
        // the first time both
        if !c.accepts_fast {
            self.actions.push(TurtleAction::Send { vpid, data: data.clone(), fast: false });
        }
        if c.accepts_fast || !c.probed_fast {
            c.probed_fast = true;
            self.actions.push(TurtleAction::Send { vpid, data, fast: true });
        }
        true
    }

    /// p3GxsTunnelService::flush(): every second, and after changes
    pub fn flush(&mut self) {
        let items = std::mem::take(&mut self.pending_items);
        for (tunnel, it) in items {
            if !self.send_encrypted(&tunnel, &it) {
                if self.contacts.contains_key(&tunnel) {
                    self.pending_items.push((tunnel, it));
                }
            }
        }
        let t = now();
        let due: Vec<u64> = self
            .pending_data
            .iter()
            .filter(|(_, d)| t > d.last_try + RESEND_DELAY)
            .map(|(k, _)| *k)
            .collect();
        for k in due {
            let Some((tunnel, it)) = self.pending_data.get(&k).map(|d| (d.tunnel, d.item.clone())) else { continue };
            if self.send_encrypted(&tunnel, &it) {
                if let Some(d) = self.pending_data.get_mut(&k) {
                    d.last_try = t;
                }
            }
        }
    }

    /// Every second: flush, keep alive, broken tunnels.
    pub fn tick(&mut self) {
        self.flush();
        let t = now();
        let mut changed = false;
        let mut drop = vec![];
        let mut keep_alive = vec![];
        for (id, c) in self.contacts.iter_mut() {
            if c.status == Status::RemotelyClosed && c.last_contact + 20 < t {
                drop.push(*id);
                continue;
            }
            if c.status == Status::CanTalk && c.last_contact + 20 + KEEP_ALIVE_TIMEOUT < t {
                info!("[gxs tunnel] tunnel {} is silent, it's down", hex::encode(id));
                c.status = Status::TunnelDn;
                c.vpid = None;
                changed = true;
                if c.client {
                    self.actions.push(TurtleAction::Redigg(c.hash));
                }
            }
            if c.status == Status::CanTalk && c.last_keep_alive + KEEP_ALIVE_TIMEOUT < t {
                keep_alive.push(*id);
                c.last_keep_alive = t;
            }
            c.received_prints.retain(|_, ts| t <= *ts + DATA_PRINT_STORAGE);
        }
        for id in keep_alive {
            self.pending_items.push((id, item(SUB_STATUS, &FLAG_KEEP_ALIVE.to_be_bytes())));
        }
        for id in drop {
            self.contacts.remove(&id);
            self.drop_pending(&id);
            changed = true;
        }
        if changed {
            self.publish_state();
        }
    }

    fn drop_pending(&mut self, tunnel: &TunnelId) {
        self.pending_data.retain(|_, d| &d.tunnel != tunnel);
        self.pending_items.retain(|(t, _)| t != tunnel);
    }

    /// startClientGxsTunnelConnection(): dig tunnels to `to`.
    fn start_client_tunnel(&mut self, to: GxsId, from: GxsId) -> TunnelId {
        let tunnel_id = make_tunnel_id(&from, &to);
        if self.contacts.contains_key(&tunnel_id) {
            return tunnel_id;
        }
        let mut hash = [0u8; 20];
        let _ = openssl::rand::rand_bytes(&mut hash[..4]);
        hash[4..].copy_from_slice(&to.0);
        let t = now();
        self.contacts.insert(
            tunnel_id,
            Contact {
                status: Status::TunnelDn,
                own_id: from,
                to_id: to,
                hash,
                client: true,
                vpid: None,
                aes_key: [0; 16],
                last_contact: t,
                last_keep_alive: t,
                received_prints: HashMap::new(),
                accepts_fast: false,
                probed_fast: false,
            },
        );
        info!("[gxs tunnel] digging tunnels from {from} to {to}");
        self.actions.push(TurtleAction::Monitor(hash));
        tunnel_id
    }

    /// closeExistingTunnel()
    fn close_tunnel(&mut self, tunnel: &TunnelId) -> bool {
        if !self.contacts.contains_key(tunnel) {
            return false;
        }
        let closing = item(SUB_STATUS, &FLAG_CLOSING.to_be_bytes());
        self.send_encrypted(tunnel, &closing);
        if let Some(c) = self.contacts.remove(tunnel) {
            if c.client {
                self.actions.push(TurtleAction::StopMonitor(c.hash));
            }
        }
        self.drop_pending(tunnel);
        true
    }

    // --- distant chat ----------------------------------------------------------------------

    pub async fn handle_cmd(&mut self, cmd: TunnelCmd) {
        match cmd {
            TunnelCmd::OpenChat { to, from, reply } => {
                let res = if !self.is_own(&from) {
                    Err("that identity is not one of yours".to_string())
                } else if self.is_own(&to) {
                    Err("that is one of your own identities".to_string())
                } else {
                    let id = self.start_client_tunnel(to, from);
                    self.saved.insert(
                        id,
                        SavedChat { id: hex::encode(id), own_id: from.to_string(), to_id: to.to_string(), own_initiative: true },
                    );
                    self.save();
                    self.publish_state();
                    Ok(hex::encode(id))
                };
                let _ = reply.send(res);
            }
            TunnelCmd::SendChat { tunnel, text, reply } => {
                // a chat from before: open the tunnel again
                if !self.contacts.contains_key(&tunnel) {
                    match self.saved.get(&tunnel).cloned() {
                        Some(s) => {
                            let (Ok(own), Ok(to)) = (hex::decode(&s.own_id), hex::decode(&s.to_id)) else {
                                let _ = reply.send(Err("broken saved chat".into()));
                                return;
                            };
                            if own.len() != 16 || to.len() != 16 {
                                let _ = reply.send(Err("broken saved chat".into()));
                                return;
                            }
                            self.start_client_tunnel(to.into(), own.into());
                        }
                        None => {
                            let _ = reply.send(Err("unknown distant chat".into()));
                            return;
                        }
                    }
                }
                let send_time = now() as u32;
                let parts = split_message(&text);
                for (i, part) in parts.iter().enumerate() {
                    let last = i + 1 == parts.len();
                    let mut flags = CHAT_FLAG_PRIVATE;
                    if !last {
                        flags |= CHAT_FLAG_PARTIAL;
                    }
                    let mut body = flags.to_be_bytes().to_vec();
                    body.extend(send_time.to_be_bytes());
                    body.extend(tlv_string(0x0057, part));
                    let chat = chat_item(CHAT_SUB_MSG, &body);
                    self.send_data(tunnel, DISTANT_CHAT_SERVICE, &chat);
                }
                self.core.record_chat(
                    HistoryChat::Distant(hex::encode(tunnel)),
                    HistoryEntry { from: String::new(), author: String::new(), text, time: send_time, incoming: false },
                );
                self.flush();
                self.publish_state();
                let _ = reply.send(Ok(()));
            }
            TunnelCmd::CloseChat { tunnel, reply } => {
                // DistantChatService::closeDistantChatConnexion(): tell the other side
                if self.contacts.get(&tunnel).map(|c| c.status == Status::CanTalk).unwrap_or(false) {
                    let mut body = CHAT_FLAG_CLOSING.to_be_bytes().to_vec();
                    body.extend(tlv_string(0x0057, ""));
                    let chat = chat_item(CHAT_SUB_STATUS, &body);
                    // straight away, the tunnel is gone afterwards
                    let counter = self.counter;
                    self.counter += 1;
                    let mut data = counter.to_be_bytes().to_vec();
                    data.extend(0u32.to_be_bytes());
                    data.extend(DISTANT_CHAT_SERVICE.to_be_bytes());
                    data.extend((chat.len() as u32).to_be_bytes());
                    data.extend(chat);
                    self.send_encrypted(&tunnel, &item(SUB_DATA, &data));
                }
                let closed = self.close_tunnel(&tunnel);
                self.publish_state();
                let _ = reply.send(closed || self.saved.contains_key(&tunnel));
            }
            TunnelCmd::Forget(tunnel) => self.forget(&tunnel),
            TunnelCmd::SetPermission(p) => {
                self.permission = p.min(2);
                if let Ok(mut g) = PERMISSION.lock() {
                    *g = self.permission;
                }
                self.save();
            }
        }
    }

    /// DistantChatService::acceptDataFromPeer() + receiveData()
    async fn distant_chat_receive(&mut self, tunnel: TunnelId, from: GxsId, client: bool, data: &[u8]) {
        // accept: always when we opened it, otherwise by permission
        if !client && self.permission != 0 {
            let allowed = self.permission == 1 && self.core.regular_contacts().await.contains(&from.to_string());
            if !allowed {
                info!("[distant chat] refusing chat from {from}");
                let mut body = CHAT_FLAG_REFUSED.to_be_bytes().to_vec();
                body.extend(tlv_string(0x0057, ""));
                let chat = chat_item(CHAT_SUB_STATUS, &body);
                self.send_data(tunnel, DISTANT_CHAT_SERVICE, &chat);
                return;
            }
        }
        if data.len() < 8 || data[1..3] != [0x00, 0x12] {
            return debug!("[distant chat] not a chat item");
        }
        let body = &data[8..];
        match data[3] {
            CHAT_SUB_MSG => {
                if body.len() < 8 {
                    return;
                }
                let flags = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let send_time = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                let Some(text) = read_tlv_string(&body[8..]) else { return };
                // p3ChatService::checkAndRebuildPartialMessage()
                let mut text = self.partial.remove(&tunnel).unwrap_or_default() + &text;
                if flags & CHAT_FLAG_PARTIAL != 0 {
                    self.partial.insert(tunnel, text);
                    return;
                }
                if text.is_empty() {
                    return;
                }
                if text.len() > 100_000 {
                    text.truncate(100_000);
                }
                let name = self.name_of(&from).await;
                info!("[distant chat] message from {name} ({from})");
                self.remember_chat(tunnel);
                let recv = now() as u32;
                self.core.record_chat(
                    HistoryChat::Distant(hex::encode(tunnel)),
                    HistoryEntry { from: name.to_owned(), author: from.to_string(), text: text.to_owned(), time: send_time, incoming: true },
                );
                let msg = ChatMessage {
                    chat_id: ChatId::from(DistantChatPeerId(tunnel)),
                    peer_alternate_nickname: name,
                    send_time,
                    recv_time: recv,
                    msg: text,
                    incoming: true,
                    online: true,
                    ..Default::default()
                };
                let _ = self.core_tx.send(Intercom::Event(EventType::ChatMessage { msg }));
            }
            CHAT_SUB_STATUS => {
                if body.len() < 4 {
                    return;
                }
                let flags = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                if flags & CHAT_FLAG_REFUSED != 0 {
                    info!("[distant chat] {from} refuses the chat");
                    self.notice(tunnel, "The other side doesn't accept distant chats from you.").await;
                }
                if flags & CHAT_FLAG_CLOSING != 0 {
                    // markDistantChatAsClosed()
                    self.notice(tunnel, "The other side closed the chat.").await;
                    self.close_tunnel(&tunnel);
                    self.publish_state();
                }
                let _ = flags & CHAT_FLAG_KEEP_ALIVE;
            }
            sub => debug!("[distant chat] ignoring chat item {sub:#x}"),
        }
    }

    /// A line in the chat window from rustyshare itself.
    async fn notice(&mut self, tunnel: TunnelId, text: &str) {
        let t = now() as u32;
        let msg = ChatMessage {
            chat_id: ChatId::from(DistantChatPeerId(tunnel)),
            peer_alternate_nickname: "rustyshare".into(),
            send_time: t,
            recv_time: t,
            msg: text.into(),
            incoming: true,
            online: true,
            ..Default::default()
        };
        let _ = self.core_tx.send(Intercom::Event(EventType::ChatMessage { msg }));
    }

    async fn name_of(&mut self, id: &GxsId) -> String {
        if let Some(n) = self.names.get(id) {
            if !n.is_empty() {
                return n.to_owned();
            }
        }
        let n = self
            .core
            .get_service_data()
            .gxs_id()
            .get_group_meta(&(*id).into())
            .await
            .map(|g| g.group_name)
            .unwrap_or_default();
        self.names.insert(*id, n.to_owned());
        n
    }

    fn remember_chat(&mut self, tunnel: TunnelId) {
        if self.saved.contains_key(&tunnel) {
            return;
        }
        let Some(c) = self.contacts.get(&tunnel) else { return };
        self.saved.insert(
            tunnel,
            SavedChat {
                id: hex::encode(tunnel),
                own_id: c.own_id.to_string(),
                to_id: c.to_id.to_string(),
                own_initiative: c.client,
            },
        );
        self.save();
    }

    fn save(&self) {
        let data = SavedChats { permission: self.permission, chats: self.saved.values().cloned().collect() };
        if let Ok(json) = serde_json::to_vec_pretty(&data) {
            if let Err(e) = std::fs::write(&self.save_file, json) {
                warn!("[distant chat] can't save {}: {e}", self.save_file.display());
            }
        }
    }

    /// Removes a chat from the list (and its tunnel).
    pub fn forget(&mut self, tunnel: &TunnelId) {
        self.close_tunnel(tunnel);
        if self.saved.remove(tunnel).is_some() {
            self.save();
        }
        self.publish_state();
    }

    /// The snapshot the web interface reads.
    fn publish_state(&self) {
        let mut list: Vec<DistantChatInfo> = vec![];
        let mut seen = HashSet::new();
        for (id, c) in &self.contacts {
            seen.insert(*id);
            list.push(DistantChatInfo {
                id: hex::encode(id),
                own_id: c.own_id.to_string(),
                to_id: c.to_id.to_string(),
                to_name: self.names.get(&c.to_id).cloned().unwrap_or_default(),
                status: match c.status {
                    Status::TunnelDn => 1,
                    Status::CanTalk => 2,
                    Status::RemotelyClosed => 3,
                },
                pending: self.pending_data.values().filter(|d| &d.tunnel == id).count(),
                own_initiative: c.client,
            });
        }
        for (id, s) in &self.saved {
            if seen.contains(id) {
                continue;
            }
            let to: Option<GxsId> = hex::decode(&s.to_id).ok().filter(|b| b.len() == 16).map(|b| b.into());
            list.push(DistantChatInfo {
                id: s.id.to_owned(),
                own_id: s.own_id.to_owned(),
                to_id: s.to_id.to_owned(),
                to_name: to.and_then(|t| self.names.get(&t).cloned()).unwrap_or_default(),
                status: 0,
                pending: 0,
                own_initiative: s.own_initiative,
            });
        }
        if let Ok(mut c) = CHATS.write() {
            *c = list;
        }
    }

    /// Looks up the names of the chat partners now and then.
    pub async fn refresh_names(&mut self) {
        let ids: Vec<GxsId> = self
            .contacts
            .values()
            .map(|c| c.to_id)
            .chain(self.saved.values().filter_map(|s| hex::decode(&s.to_id).ok().filter(|b| b.len() == 16).map(|b| b.into())))
            .collect();
        for id in ids {
            if self.names.get(&id).map(|n| n.is_empty()).unwrap_or(true) {
                self.name_of(&id).await;
            }
        }
        self.publish_state();
    }
}

// --- helpers -------------------------------------------------------------------------------

/// An RsGxsTunnel item: header (version 2, service 0x0028, sub type, size) + body.
fn item(sub: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x02, SERVICE[0], SERVICE[1], sub];
    out.extend(((body.len() + 8) as u32).to_be_bytes());
    out.extend(body);
    out
}

/// An RsChatItem (service 0x0012).
fn chat_item(sub: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x02, 0x00, 0x12, sub];
    out.extend(((body.len() + 8) as u32).to_be_bytes());
    out.extend(body);
    out
}

fn tlv_string(tag: u16, s: &str) -> Vec<u8> {
    let mut out = tag.to_be_bytes().to_vec();
    out.extend(((s.len() + 6) as u32).to_be_bytes());
    out.extend(s.as_bytes());
    out
}

fn read_tlv_string(data: &[u8]) -> Option<String> {
    let (tlv, _) = take_tlv(data)?;
    Some(String::from_utf8_lossy(&tlv[6..]).into_owned())
}

/// The first TLV (header included) and the rest.
pub(crate) fn take_tlv(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_be_bytes(data.get(2..6)?.try_into().ok()?) as usize;
    if len < 6 || len > data.len() {
        return None;
    }
    Some((&data[..len], &data[len..]))
}

fn split_message(text: &str) -> Vec<String> {
    let mut parts = vec![];
    let mut rest = text;
    while rest.len() > CHAT_MAX_PART {
        let mut cut = CHAT_MAX_PART;
        while !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        parts.push(rest[..cut].to_owned());
        rest = &rest[cut..];
    }
    parts.push(rest.to_owned());
    parts
}

/// randomHashFromDestinationGxsId() reversed: the last 16 bytes
fn destination_from_hash(hash: &Hash) -> GxsId {
    hash[4..].to_vec().into()
}

/// makeGxsTunnelId(): SHA1(smaller id | bigger id), first 16 bytes
fn make_tunnel_id(own: &GxsId, distant: &GxsId) -> TunnelId {
    let mut mem = vec![];
    if own < distant {
        mem.extend(own.0);
        mem.extend(distant.0);
    } else {
        mem.extend(distant.0);
        mem.extend(own.0);
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&openssl::sha::sha1(&mem)[..16]);
    id
}

fn new_dh() -> Result<Dh<Private>, String> {
    let p = BigNum::from_hex_str(DH_PRIME_2048).map_err(|e| e.to_string())?;
    let g = BigNum::from_u32(5).map_err(|e| e.to_string())?;
    Dh::from_pqg(p, None, g)
        .and_then(|dh| dh.generate_key())
        .map_err(|e| e.to_string())
}

pub(crate) fn rsa_sha1_sign(rsa: &Rsa<Private>, data: &[u8]) -> Result<Vec<u8>, String> {
    let pkey = PKey::from_rsa(rsa.to_owned()).map_err(|e| e.to_string())?;
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey).map_err(|e| e.to_string())?;
    signer.update(data).map_err(|e| e.to_string())?;
    signer.sign_to_vec().map_err(|e| e.to_string())
}

pub(crate) fn rsa_sha1_verify(key: &TlvPublicRSAKey, data: &[u8], sig: &[u8]) -> Result<bool, String> {
    let rsa = Rsa::public_key_from_der_pkcs1(key.key_data.as_slice()).map_err(|e| e.to_string())?;
    let pkey = PKey::from_rsa(rsa).map_err(|e| e.to_string())?;
    let mut v = Verifier::new(MessageDigest::sha1(), &pkey).map_err(|e| e.to_string())?;
    v.update(data).map_err(|e| e.to_string())?;
    v.verify(sig).map_err(|e| e.to_string())
}

/// GxsSecurity::checkPublicKey(): a public key whose id matches it
pub(crate) fn check_public_key(key: &TlvPublicRSAKey) -> bool {
    let Ok(rsa) = Rsa::public_key_from_der_pkcs1(key.key_data.as_slice()) else { return false };
    let id: GxsId = key.key_id.to_owned().into();
    let n = rsa.n().to_vec();
    let mut ne = n.clone();
    ne.extend(rsa.e().to_vec());
    let new_style = &openssl::sha::sha1(&ne)[..16];
    let old_style = n.get(..16).unwrap_or_default();
    id.0 == new_style || id.0 == old_style
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let pkey = PKey::hmac(key).map_err(|e| e.to_string())?;
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey).map_err(|e| e.to_string())?;
    signer.update(data).map_err(|e| e.to_string())?;
    signer.sign_to_vec().map_err(|e| e.to_string())
}

/// RsAES: AES-256-CBC, key and IV from EVP_BytesToKey(SHA1, salt, 5 rounds)
fn aes_key_iv(key: &[u8; 16], salt: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let kiv = openssl::pkcs5::bytes_to_key(Cipher::aes_256_cbc(), MessageDigest::sha1(), key, Some(salt), 5)
        .map_err(|e| e.to_string())?;
    Ok((kiv.key, kiv.iv.unwrap_or_default()))
}

fn aes_encrypt(key: &[u8; 16], salt: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let (k, iv) = aes_key_iv(key, salt)?;
    openssl::symm::encrypt(Cipher::aes_256_cbc(), &k, Some(&iv), data).map_err(|e| e.to_string())
}

fn aes_decrypt(key: &[u8; 16], salt: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let (k, iv) = aes_key_iv(key, salt)?;
    openssl::symm::decrypt(Cipher::aes_256_cbc(), &k, Some(&iv), data).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_round_trip() {
        let key = [7u8; 16];
        let iv = [1, 2, 3, 4, 5, 6, 7, 8];
        let data = b"hello distant chat".to_vec();
        let enc = aes_encrypt(&key, &iv, &data).unwrap();
        assert_eq!(enc.len() % 16, 0);
        assert_eq!(aes_decrypt(&key, &iv, &enc).unwrap(), data);
    }

    #[test]
    fn tunnel_id_is_symmetric() {
        let a: GxsId = vec![1u8; 16].into();
        let b: GxsId = vec![2u8; 16].into();
        assert_eq!(make_tunnel_id(&a, &b), make_tunnel_id(&b, &a));
    }

    #[test]
    fn dh_agrees() {
        let a = new_dh().unwrap();
        let b = new_dh().unwrap();
        let ka = a.compute_key(b.public_key()).unwrap();
        let kb = b.compute_key(a.public_key()).unwrap();
        assert_eq!(ka, kb);
    }
}
