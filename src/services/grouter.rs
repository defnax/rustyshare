//! Global router (service 0x0018), like libretroshare's `grouter/p3grouter.cc`: delivers
//! data to a GXS identity somewhere in the network, used by distant mail (client
//! service 0x1001).
//!
//! - a data item is encrypted for the destination identity (GxsSecurity::encrypt:
//!   RSA encrypted AES-128 key, IV, AES-128-CBC) and signed by the sender
//! - items travel in "transactions": the serialised item cut in 15000 byte chunks,
//!   the receiver acknowledges a complete item; to friends as service 0x0018 packets,
//!   through turtle tunnels as turtle data
//! - friends store and forward items; whoever has no other friend for it digs turtle
//!   tunnels to the hash SHA1(destination id | 0 0 | client service id)
//! - the destination answers with a receipt signed by the destination identity,
//!   which travels back the way the item came
//!
//! Not like RetroShare: no routing matrix (friends are chosen at random).
//! The router lives in the turtle task (`turtle.rs`) because it needs its tunnels.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use log::{debug, info, warn};
use nanorand::{Rng, WyRand};
use openssl::{
    rsa::{Padding, Rsa},
    symm::Cipher,
};
use retroshare_compat::{
    basics::{GxsId, SslId},
    serde::{from_retroshare_wire_result, to_retroshare_wire},
    services::ServiceType,
    tlv::{
        tlv_keys::{KeyId, TlvKeySignature, TlvKeySignatureInner},
        Tlv,
    },
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::{
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::{intercom::Intercom, DataCore},
    services::gxs_tunnel::{rsa_sha1_sign, rsa_sha1_verify, take_tlv, Hash, TurtleAction, Vpid},
};

/// GROUTER_CLIENT_ID_MESSAGES
pub const CLIENT_MESSAGES: u32 = 0x1001;

const SERVICE: [u8; 2] = [0x00, 0x18];
const SUB_DATA: u8 = 0x07;
const SUB_RECEIPT: u8 = 0x08;
const SUB_CHUNK: u8 = 0x10;
const SUB_ACK: u8 = 0x11;

const FLAG_ENCRYPTED: u32 = 0x1;

const CHUNK_SIZE: usize = 15000;
const MAX_DATA_SIZE: usize = 2 * 1024 * 1024;
const MAX_DUPLICATION: u32 = 10;
const MAX_BRANCHING: usize = 3;

const MAX_TUNNEL_WAIT_TIME: u64 = 60;
const MAX_TUNNEL_UNMANAGED_TIME: u64 = 600;
const MAX_DELAY_FOR_RESEND: u64 = 2 * 86400 + 300;
const MAX_DESTINATION_KEEP_TIME: u64 = 20 * 86400;
const MAX_RECEIPT_KEEP_TIME: u64 = 20 * 86400;
const ITEM_MAX_CACHE_KEEP_TIME: u64 = 2 * 86400;
const TUNNEL_OK_WAIT_TIME: u64 = 2;
const MAX_TRANSACTION_ACK_WAITING_TIME: u64 = 60;
const DIRECT_FRIEND_TRY_DELAY: u64 = 20;
const MAX_INACTIVE_DATA_PIPE_DELAY: u64 = 300;
const MISSING_KEY_TIMEOUT: u64 = 600;
const MISSING_KEY_CHECK_EVERY: u64 = 30;

// data status
const STATUS_PENDING: u32 = 1;
const STATUS_SENT: u32 = 2;
const STATUS_RECEIPT_OK: u32 = 3;
const STATUS_ONGOING: u32 = 4;
const STATUS_DONE: u32 = 5;
// tunnel status
const TUNNEL_UNMANAGED: u32 = 0;
const TUNNEL_PENDING: u32 = 1;
const TUNNEL_READY: u32 = 2;
// routing flags
const ALLOW_TUNNELS: u32 = 0x1;
const ALLOW_FRIENDS: u32 = 0x2;
const IS_ORIGIN: u32 = 0x4;
const IS_DESTINATION: u32 = 0x8;

const SAVE_FILE: &str = "rustyshare_grouter.json";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

// --- interface for the mail service --------------------------------------------------

pub enum GRouterCmd {
    /// send `data` (a serialised RsMsgItem) from `from` to `to`; the mail store hears
    /// about the receipt through `mail_id` / `mail_sub` (outbox entry)
    SendMail { from: GxsId, to: GxsId, data: Vec<u8>, mail_id: u32, mail_sub: u32 },
    /// RS_DISTANT_MESSAGING_CONTACT_PERMISSION_FLAG_*: 0 everybody, 1 contacts, 2 nobody
    SetPermission(u32),
}

static CMD: OnceLock<UnboundedSender<GRouterCmd>> = OnceLock::new();
static PACKETS: OnceLock<UnboundedSender<Packet>> = OnceLock::new();
static PERMISSION: Mutex<u32> = Mutex::new(0);

pub fn command(cmd: GRouterCmd) -> bool {
    CMD.get().map(|tx| tx.send(cmd).is_ok()).unwrap_or(false)
}

pub fn permission() -> u32 {
    PERMISSION.lock().map(|p| *p).unwrap_or(0)
}

/// Packets of service 0x0018 from friends (see `GRouterService`).
pub fn incoming_packet(packet: Packet) {
    if let Some(tx) = PACKETS.get() {
        let _ = tx.send(packet);
    }
}

// --- items ---------------------------------------------------------------------------

/// RsGRouterGenericDataItem
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DataItem {
    routing_id: u64,
    dest: [u8; 16],
    service_id: u32,
    #[serde(with = "hex")]
    data: Vec<u8>,
    /// RsTlvKeySignature, as on the wire
    #[serde(with = "hex")]
    signature: Vec<u8>,
    duplication: u32,
    flags: u32,
}

impl DataItem {
    /// the signed part (SIGNATURE | SKIP_HEADER)
    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = self.routing_id.to_be_bytes().to_vec();
        out.extend(self.dest);
        out.extend(self.service_id.to_be_bytes());
        out.extend((self.data.len() as u32).to_be_bytes());
        out.extend(&self.data);
        out
    }
    fn to_wire(&self) -> Vec<u8> {
        let mut body = self.signed_bytes();
        body.extend(&self.signature);
        body.extend(self.duplication.to_be_bytes());
        body.extend(self.flags.to_be_bytes());
        item(SUB_DATA, &body)
    }
    fn parse(body: &[u8]) -> Option<DataItem> {
        let routing_id = u64::from_be_bytes(body.get(0..8)?.try_into().ok()?);
        let dest: [u8; 16] = body.get(8..24)?.try_into().ok()?;
        let service_id = u32::from_be_bytes(body.get(24..28)?.try_into().ok()?);
        let size = u32::from_be_bytes(body.get(28..32)?.try_into().ok()?) as usize;
        let data = body.get(32..32 + size)?.to_vec();
        let (sig, rest) = take_tlv(&body[32 + size..])?;
        let duplication = u32::from_be_bytes(rest.get(0..4)?.try_into().ok()?).clamp(1, MAX_DUPLICATION);
        let flags = u32::from_be_bytes(rest.get(4..8)?.try_into().ok()?);
        Some(DataItem { routing_id, dest, service_id, data, signature: sig.to_vec(), duplication, flags })
    }
    /// computeDataItemHash(): SHA1(signed part | signature)
    fn hash(&self) -> [u8; 20] {
        let mut b = self.signed_bytes();
        b.extend(&self.signature);
        openssl::sha::sha1(&b)
    }
}

/// RsGRouterSignedReceiptItem
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Receipt {
    routing_id: u64,
    flags: u32,
    dest: [u8; 16],
    service_id: u32,
    data_hash: [u8; 20],
    #[serde(with = "hex")]
    signature: Vec<u8>,
}

impl Receipt {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = self.routing_id.to_be_bytes().to_vec();
        out.extend(self.flags.to_be_bytes());
        out.extend(self.dest);
        out.extend(self.service_id.to_be_bytes());
        out.extend(self.data_hash);
        out
    }
    fn to_wire(&self) -> Vec<u8> {
        let mut body = self.signed_bytes();
        body.extend(&self.signature);
        item(SUB_RECEIPT, &body)
    }
    fn parse(body: &[u8]) -> Option<Receipt> {
        let routing_id = u64::from_be_bytes(body.get(0..8)?.try_into().ok()?);
        let flags = u32::from_be_bytes(body.get(8..12)?.try_into().ok()?);
        let dest: [u8; 16] = body.get(12..28)?.try_into().ok()?;
        let service_id = u32::from_be_bytes(body.get(28..32)?.try_into().ok()?);
        let data_hash: [u8; 20] = body.get(32..52)?.try_into().ok()?;
        let (sig, _) = take_tlv(&body[52..])?;
        Some(Receipt { routing_id, flags, dest, service_id, data_hash, signature: sig.to_vec() })
    }
}

fn item(sub: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x02, SERVICE[0], SERVICE[1], sub];
    out.extend(((body.len() + 8) as u32).to_be_bytes());
    out.extend(body);
    out
}

/// makeTunnelHash()
pub fn tunnel_hash(dest: &[u8; 16], client: u32) -> Hash {
    let mut b = [0u8; 20];
    b[..16].copy_from_slice(dest);
    b[18] = (client >> 8) as u8;
    b[19] = client as u8;
    openssl::sha::sha1(&b)
}

/// The key id and signature bytes of an RsTlvKeySignature.
fn read_signature(tlv: &[u8]) -> Option<(GxsId, Vec<u8>)> {
    let parsed = std::panic::catch_unwind(|| {
        let sig: Result<TlvKeySignature, _> = from_retroshare_wire_result(&mut tlv.to_vec());
        sig.ok()
    });
    let sig = parsed.ok()??;
    Some((sig.key_id.to_owned().into(), sig.sign_data.to_vec()))
}

/// GxsSecurity::encrypt() for one key (EVP_Seal, AES-128-CBC):
/// u32 encrypted key length | RSA encrypted AES key | IV (16) | AES-128-CBC data
fn encrypt_for(key_der: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let rsa = Rsa::public_key_from_der_pkcs1(key_der).map_err(|e| e.to_string())?;
    let mut aes = [0u8; 16];
    let mut iv = [0u8; 16];
    openssl::rand::rand_bytes(&mut aes).map_err(|e| e.to_string())?;
    openssl::rand::rand_bytes(&mut iv).map_err(|e| e.to_string())?;
    let mut ek = vec![0u8; rsa.size() as usize];
    let n = rsa.public_encrypt(&aes, &mut ek, Padding::PKCS1).map_err(|e| e.to_string())?;
    ek.truncate(n);
    let enc = openssl::symm::encrypt(Cipher::aes_128_cbc(), &aes, Some(&iv), data).map_err(|e| e.to_string())?;
    let mut out = (ek.len() as u32).to_be_bytes().to_vec();
    out.extend(ek);
    out.extend(iv);
    out.extend(enc);
    Ok(out)
}

/// GxsSecurity::decrypt() for one key
fn decrypt_with(private_der: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let rsa = Rsa::private_key_from_der(private_der).map_err(|e| e.to_string())?;
    let eklen = u32::from_be_bytes(data.get(0..4).ok_or("short")?.try_into().map_err(|_| "short")?) as usize;
    if eklen > 512 {
        return Err("bad key length".into());
    }
    let ek = data.get(4..4 + eklen).ok_or("short")?;
    let iv = data.get(4 + eklen..20 + eklen).ok_or("short")?;
    let enc = data.get(20 + eklen..).ok_or("short")?;
    let mut aes = vec![0u8; rsa.size() as usize];
    let n = rsa.private_decrypt(ek, &mut aes, Padding::PKCS1).map_err(|e| e.to_string())?;
    aes.truncate(n);
    if aes.len() != 16 {
        return Err("bad AES key".into());
    }
    openssl::symm::decrypt(Cipher::aes_128_cbc(), &aes, Some(iv), enc).map_err(|e| e.to_string())
}

// --- state ---------------------------------------------------------------------------

/// Where an item came from / goes to: a friend or a turtle tunnel.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum Route {
    Friend(String),
    Tunnel(#[serde(with = "hex")] Vec<u8>),
}

/// GRouterRoutingInfo
#[derive(Serialize, Deserialize)]
struct Routing {
    item: DataItem,
    receipt: Option<Receipt>,
    status: u32,
    #[serde(skip)]
    tunnel_status: u32,
    flags: u32,
    item_hash: [u8; 20],
    tunnel_hash: Hash,
    #[serde(default)]
    incoming: HashSet<Route>,
    received: u64,
    last_sent: u64,
    #[serde(skip)]
    last_tunnel_request: u64,
    #[serde(skip)]
    transaction_ts: u64,
    /// origin: the outbox entry of the mail
    #[serde(default)]
    mail: Option<(u32, u32)>,
}

#[derive(Default)]
struct TunnelInfo {
    vpids: Vec<Vpid>,
    last_ok: u64,
}

#[derive(Default)]
struct Pipe {
    buf: Vec<u8>,
    total: usize,
    last: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct Saved {
    #[serde(default)]
    permission: u32,
    #[serde(default)]
    pending: Vec<(u64, Routing)>,
    /// hashes of received mails (p3MsgService::mRecentlyReceivedMessageHashes)
    #[serde(default)]
    recent: Vec<(String, u64)>,
}

pub struct GRouter {
    core: Arc<DataCore>,
    core_tx: UnboundedSender<Intercom>,
    own_ids: Arc<RwLock<HashSet<GxsId>>>,
    rng: WyRand,
    pending: HashMap<u64, Routing>,
    tunnels: HashMap<Hash, TunnelInfo>,
    pipes: HashMap<Route, Pipe>,
    recent: HashMap<[u8; 20], u64>,
    /// items from unknown authors, checked again later (mMissingKeyQueue)
    missing_key: Vec<(DataItem, Route, u64)>,
    last_missing_check: u64,
    actions: Vec<TurtleAction>,
    /// hashes we dig tunnels for
    dug: HashSet<Hash>,
    permission: u32,
    save_file: PathBuf,
    changed: bool,
    last_save: u64,
    ticks: u64,
}

impl GRouter {
    pub async fn new(
        core: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        own_ids: Arc<RwLock<HashSet<GxsId>>>,
    ) -> (Self, UnboundedReceiver<GRouterCmd>, UnboundedReceiver<Packet>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let _ = CMD.set(tx);
        let (ptx, prx) = tokio::sync::mpsc::unbounded_channel();
        let _ = PACKETS.set(ptx);

        let save_file = core.get_config_dir().await.join(SAVE_FILE);
        let saved: Saved = std::fs::read(&save_file)
            .ok()
            .and_then(|d| serde_json::from_slice(&d).map_err(|e| warn!("[grouter] can't read {}: {e}", save_file.display())).ok())
            .unwrap_or_default();
        if let Ok(mut p) = PERMISSION.lock() {
            *p = saved.permission;
        }
        let mut pending: HashMap<u64, Routing> = saved.pending.into_iter().collect();
        for r in pending.values_mut() {
            if r.status == STATUS_ONGOING {
                r.status = STATUS_PENDING;
            }
        }
        let recent = saved
            .recent
            .into_iter()
            .filter_map(|(h, t)| Some((hex::decode(h).ok()?.try_into().ok()?, t)))
            .collect();
        info!("[grouter] {} items in the cache", pending.len());
        (
            GRouter {
                core: core.clone(),
                core_tx,
                own_ids,
                rng: WyRand::new(),
                pending,
                tunnels: HashMap::new(),
                pipes: HashMap::new(),
                recent,
                missing_key: vec![],
                last_missing_check: 0,
                actions: vec![],
                dug: HashSet::new(),
                permission: saved.permission,
                save_file,
                changed: false,
                last_save: 0,
                ticks: 0,
            },
            rx,
            prx,
        )
    }

    pub fn take_actions(&mut self) -> Vec<TurtleAction> {
        std::mem::take(&mut self.actions)
    }

    fn own_ids(&self) -> HashSet<GxsId> {
        self.own_ids.read().map(|o| o.clone()).unwrap_or_default()
    }

    // --- turtle side ------------------------------------------------------------------

    /// p3GRouter::handleTunnelRequest(): the hash of one of our identities
    pub fn handle_tunnel_request(&self, hash: &Hash) -> bool {
        self.own_ids().iter().any(|id| &tunnel_hash(&id.0, CLIENT_MESSAGES) == hash)
    }

    /// p3GRouter::addVirtualPeer()
    pub fn add_virtual_peer(&mut self, hash: Hash, vpid: Vpid, client: bool) {
        if client {
            let mut found = false;
            for r in self.pending.values_mut() {
                if r.tunnel_hash == hash {
                    r.tunnel_status = TUNNEL_READY;
                    found = true;
                }
            }
            if !found {
                return debug!("[grouter] tunnel for a hash we don't need anymore");
            }
        }
        let t = self.tunnels.entry(hash).or_default();
        if !t.vpids.contains(&vpid) {
            t.vpids.push(vpid);
        }
        t.last_ok = now();
    }

    /// p3GRouter::removeVirtualPeer()
    pub fn remove_virtual_peer(&mut self, hash: &Hash, vpid: &Vpid) {
        let Some(t) = self.tunnels.get_mut(hash) else { return };
        t.vpids.retain(|v| v != vpid);
        if t.vpids.is_empty() {
            self.tunnels.remove(hash);
            for r in self.pending.values_mut() {
                if &r.tunnel_hash == hash && r.tunnel_status == TUNNEL_READY {
                    r.tunnel_status = TUNNEL_PENDING;
                }
            }
        }
        self.pipes.remove(&Route::Tunnel(vpid.to_vec()));
    }

    fn tunnel_alive(&self, vpid: &[u8]) -> bool {
        self.tunnels.values().any(|t| t.vpids.iter().any(|v| v.as_slice() == vpid))
    }

    /// p3GRouter::receiveTurtleData()
    pub async fn receive_turtle_data(&mut self, vpid: Vpid, data: &[u8]) {
        if data.len() < 8 || data[1..3] != SERVICE {
            return;
        }
        self.handle_transaction(Route::Tunnel(vpid.to_vec()), data[3], &data[8..]).await;
    }

    /// service 0x0018 packets from friends
    pub async fn receive_packet(&mut self, packet: Packet) {
        let header: ServiceHeader = packet.header.to_owned().into();
        let route = Route::Friend(packet.peer_id.to_string());
        self.handle_transaction(route, header.sub_type, &packet.payload).await;
    }

    async fn handle_transaction(&mut self, route: Route, sub: u8, body: &[u8]) {
        match sub {
            SUB_CHUNK => {
                // u64 id, u32 start, u32 size, u32 total, data
                if body.len() < 20 {
                    return;
                }
                let start = u32::from_be_bytes(body[8..12].try_into().unwrap_or_default()) as usize;
                let size = u32::from_be_bytes(body[12..16].try_into().unwrap_or_default()) as usize;
                let total = u32::from_be_bytes(body[16..20].try_into().unwrap_or_default()) as usize;
                let Some(chunk) = body.get(20..20 + size) else { return };
                // GRouterDataInfo::addDataChunk()
                if total > MAX_DATA_SIZE + 10000 || size > total || start >= total {
                    self.pipes.remove(&route);
                    return;
                }
                let pipe = self.pipes.entry(route.clone()).or_default();
                pipe.last = now();
                if start == 0 {
                    pipe.buf.clear();
                    pipe.total = total;
                } else if pipe.buf.len() != start || pipe.total != total {
                    self.pipes.remove(&route);
                    return;
                }
                pipe.buf.extend(chunk);
                if pipe.buf.len() < pipe.total {
                    return;
                }
                let whole = std::mem::take(&mut pipe.buf);
                self.pipes.remove(&route);
                if whole.len() < 8 || whole[1..3] != SERVICE {
                    return;
                }
                let inner = &whole[8..];
                match whole[3] {
                    SUB_DATA => {
                        let Some(data) = DataItem::parse(inner) else { return warn!("[grouter] broken data item") };
                        info!(
                            "[grouter] item {:x} for {} from {route:?}",
                            data.routing_id,
                            hex::encode(data.dest)
                        );
                        self.send_transaction(&route, &item(SUB_ACK, &data.routing_id.to_be_bytes()));
                        self.handle_data(data, route).await;
                    }
                    SUB_RECEIPT => {
                        let Some(r) = Receipt::parse(inner) else { return warn!("[grouter] broken receipt") };
                        info!("[grouter] receipt for item {:x} from {route:?}", r.routing_id);
                        self.send_transaction(&route, &item(SUB_ACK, &r.routing_id.to_be_bytes()));
                        self.handle_receipt(r, route).await;
                    }
                    other => debug!("[grouter] unexpected item {other:#x} in a transaction"),
                }
            }
            SUB_ACK => {
                let Some(id) = body.get(0..8).map(|b| u64::from_be_bytes(b.try_into().unwrap_or_default())) else { return };
                info!("[grouter] {route:?} took item {id:x}");
                if let Some(r) = self.pending.get_mut(&id) {
                    if r.status == STATUS_ONGOING {
                        r.status = STATUS_SENT;
                        r.last_sent = now();
                        self.changed = true;
                    }
                }
            }
            other => debug!("[grouter] ignoring item {other:#x}"),
        }
    }

    /// locked_sendTransactionData(): one item to a friend or into a tunnel
    fn send_transaction(&mut self, route: &Route, wire: &[u8]) {
        match route {
            Route::Tunnel(v) => {
                let Ok(vpid) = v.as_slice().try_into() else { return };
                self.actions.push(TurtleAction::Send { vpid, data: wire.to_vec(), fast: false });
            }
            Route::Friend(id) => {
                let Some(peer) = self.connected_friend(id) else { return };
                let payload = wire[8..].to_vec();
                let header = ServiceHeader::new(ServiceType::GRouter, wire[3], &payload);
                let _ = self.core_tx.send(Intercom::Send(Packet::new(header.into(), payload, peer)));
            }
        }
    }

    /// sliceDataItem() + sending of all chunks
    fn send_sliced(&mut self, route: &Route, id: u64, wire: &[u8]) {
        let total = wire.len();
        let mut offset = 0;
        while offset < total {
            let size = (total - offset).min(CHUNK_SIZE);
            let mut body = id.to_be_bytes().to_vec();
            body.extend((offset as u32).to_be_bytes());
            body.extend((size as u32).to_be_bytes());
            body.extend((total as u32).to_be_bytes());
            body.extend(&wire[offset..offset + size]);
            self.send_transaction(route, &item(SUB_CHUNK, &body));
            offset += size;
        }
    }

    fn connected_friends(&self) -> Vec<Arc<SslId>> {
        self.core
            .get_locations()
            .iter()
            .filter(|l| l.is_connected())
            .map(|l| l.get_location_id())
            .collect()
    }

    fn connected_friend(&self, id: &str) -> Option<Arc<SslId>> {
        self.connected_friends().into_iter().find(|p| p.to_string() == id)
    }

    fn route_alive(&self, route: &Route) -> bool {
        match route {
            Route::Tunnel(v) => self.tunnel_alive(v),
            Route::Friend(id) => self.connected_friend(id).is_some(),
        }
    }

    // --- signatures ----------------------------------------------------------------------

    /// Ok(true) good, Ok(false) bad, Err(()) key not available
    async fn verify(&self, signed: &[u8], sig_tlv: &[u8]) -> Result<bool, ()> {
        let Some((signer, sig)) = read_signature(sig_tlv) else { return Ok(false) };
        if self.core.reputation_is_banned(&signer.to_string()) {
            warn!("[grouter] item signed by banned identity {signer}");
            return Ok(false);
        }
        let Some(key) = self.core.get_service_data().gxs_id().get_pub_keys_by_id(&signer).await else {
            return Err(());
        };
        Ok(rsa_sha1_verify(&key, signed, &sig).unwrap_or(false))
    }

    async fn sign(&self, data: &[u8], id: &GxsId) -> Result<Vec<u8>, String> {
        let private = self
            .core
            .get_service_data()
            .gxs_id()
            .get_priv_keys_by_id(id)
            .await
            .ok_or(format!("no private key for {id}"))?;
        let rsa = Rsa::private_key_from_der(private.key_data.as_slice()).map_err(|e| e.to_string())?;
        let sig = rsa_sha1_sign(&rsa, data)?;
        let tlv: TlvKeySignature = Tlv(TlvKeySignatureInner { key_id: KeyId::from(*id), sign_data: sig.into() });
        Ok(to_retroshare_wire(&tlv))
    }

    // --- incoming items -----------------------------------------------------------------

    /// p3GRouter::handleIncomingDataItem()
    async fn handle_data(&mut self, data: DataItem, route: Route) {
        let item_hash = data.hash();
        let dest = GxsId::from(data.dest.to_vec());
        let for_us = data.service_id == CLIENT_MESSAGES && self.own_ids().contains(&dest);

        let mut known = false;
        let mut receipt = None;
        if let Some(r) = self.pending.get(&data.routing_id) {
            if r.item_hash != item_hash {
                return warn!("[grouter] item {:x} with a different hash, dropped", data.routing_id);
            }
            known = true;
            receipt = r.receipt.clone();
        }
        if !known {
            match self.verify(&data.signed_bytes(), &data.signature).await {
                Ok(true) => {}
                Ok(false) => return warn!("[grouter] wrong signature on item {:x}, dropped", data.routing_id),
                Err(()) => {
                    info!("[grouter] item {:x} from an unknown identity, waiting for its key", data.routing_id);
                    if self.missing_key.len() < 100 {
                        self.missing_key.push((data, route, now() + MISSING_KEY_TIMEOUT));
                    }
                    return;
                }
            }
        }
        let signer = read_signature(&data.signature).map(|(id, _)| id);

        if for_us && !known {
            let Some(signer) = signer else { return };
            let mut r = Receipt {
                routing_id: data.routing_id,
                flags: 0,
                dest: signer.0,
                service_id: data.service_id,
                data_hash: item_hash,
                signature: vec![],
            };
            match self.sign(&r.signed_bytes(), &dest).await {
                Ok(s) => r.signature = s,
                Err(e) => return warn!("[grouter] can't sign the receipt: {e}"),
            }
            receipt = Some(r);
        }

        let t = now();
        let entry = self.pending.entry(data.routing_id).or_insert_with(|| {
            let mut item = data.clone();
            let (flags, status) = if for_us {
                item.data.clear();
                (IS_DESTINATION | ALLOW_FRIENDS, STATUS_RECEIPT_OK)
            } else {
                (ALLOW_FRIENDS, STATUS_PENDING) // tunnels not just yet
            };
            Routing {
                tunnel_hash: tunnel_hash(&item.dest, item.service_id),
                item,
                receipt: receipt.clone(),
                status,
                tunnel_status: TUNNEL_UNMANAGED,
                flags,
                item_hash,
                incoming: HashSet::new(),
                received: t,
                last_sent: 0,
                last_tunnel_request: 0,
                transaction_ts: 0,
                mail: None,
            }
        });
        entry.incoming.insert(route);
        self.changed = true;

        if for_us && !known {
            if let Some(signer) = signer {
                self.deliver(&data, signer, dest).await;
            }
        }
    }

    /// decrypts and hands the mail to the mail store (p3MsgService::receiveGRouterData())
    async fn deliver(&mut self, data: &DataItem, from: GxsId, to: GxsId) {
        let Some(private) = self.core.get_service_data().gxs_id().get_priv_keys_by_id(&to).await else {
            return warn!("[grouter] no private key for {to}");
        };
        let clear = if data.flags & FLAG_ENCRYPTED != 0 {
            match decrypt_with(private.key_data.as_slice(), &data.data) {
                Ok(c) => c,
                Err(e) => return warn!("[grouter] can't decrypt item {:x}: {e}", data.routing_id),
            }
        } else {
            data.data.clone()
        };
        // acceptDataFromPeer()
        let accept = match self.permission {
            0 => true,
            1 => self.core.regular_contacts().await.contains(&from.to_string()),
            _ => false,
        };
        if !accept {
            return info!("[grouter] distant mail from {from} refused (permission)");
        }
        let hash = openssl::sha::sha1(&clear);
        if self.recent.contains_key(&hash) {
            return debug!("[grouter] mail received before");
        }
        self.recent.insert(hash, now());
        self.changed = true;
        crate::mail::receive_distant(&clear, &from.to_string(), &to.to_string());
    }

    /// p3GRouter::handleIncomingReceiptItem()
    async fn handle_receipt(&mut self, receipt: Receipt, route: Route) {
        let Some(r) = self.pending.get(&receipt.routing_id) else {
            return info!("[grouter] receipt for an unknown item {:x}", receipt.routing_id);
        };
        if receipt.data_hash != r.item_hash {
            return warn!("[grouter] receipt with a wrong hash");
        }
        let origin = r.flags & IS_ORIGIN != 0;
        match self.verify(&receipt.signed_bytes(), &receipt.signature).await {
            Ok(true) => {}
            Err(()) if !origin => {} // can't check it, pass it on anyway
            _ => return warn!("[grouter] receipt with a wrong signature"),
        }
        let Some(r) = self.pending.get_mut(&receipt.routing_id) else { return };
        if origin {
            r.status = STATUS_DONE;
            if let Some((mail_id, sub)) = r.mail {
                info!("[grouter] mail {mail_id} arrived at its destination");
                crate::mail::distant_delivered(mail_id, sub);
            }
        } else {
            r.status = STATUS_RECEIPT_OK;
            r.receipt = Some(receipt);
        }
        let _ = route;
        self.changed = true;
    }

    // --- sending -----------------------------------------------------------------------

    pub async fn handle_cmd(&mut self, cmd: GRouterCmd) {
        match cmd {
            GRouterCmd::SendMail { from, to, data, mail_id, mail_sub } => {
                // to one of our own identities: no need to travel
                if self.own_ids().contains(&to) {
                    crate::mail::receive_distant(&data, &from.to_string(), &to.to_string());
                    crate::mail::distant_delivered(mail_id, mail_sub);
                    return;
                }
                if let Err(e) = self.send_data(from, to, data, mail_id, mail_sub).await {
                    warn!("[grouter] can't send mail {mail_id} to {to}: {e}");
                    crate::mail::distant_failed(mail_id, mail_sub);
                }
            }
            GRouterCmd::SetPermission(p) => {
                self.permission = p.min(2);
                if let Ok(mut g) = PERMISSION.lock() {
                    *g = self.permission;
                }
                self.changed = true;
                self.save();
            }
        }
    }

    /// p3GRouter::sendData()
    async fn send_data(&mut self, from: GxsId, to: GxsId, data: Vec<u8>, mail_id: u32, mail_sub: u32) -> Result<(), String> {
        if data.len() > MAX_DATA_SIZE {
            return Err("too big".into());
        }
        let key = self
            .core
            .get_service_data()
            .gxs_id()
            .get_pub_keys_by_id(&to)
            .await
            .ok_or("the identity's key is not known (yet)")?;
        let encrypted = encrypt_for(key.key_data.as_slice(), &data)?;
        let mut routing_id = self.rng.generate::<u64>();
        while self.pending.contains_key(&routing_id) {
            routing_id = self.rng.generate::<u64>();
        }
        let mut item = DataItem {
            routing_id,
            dest: to.0,
            service_id: CLIENT_MESSAGES,
            data: encrypted,
            signature: vec![],
            duplication: MAX_DUPLICATION,
            flags: FLAG_ENCRYPTED,
        };
        item.signature = self.sign(&item.signed_bytes(), &from).await?;
        if self.verify(&item.signed_bytes(), &item.signature).await != Ok(true) {
            return Err("self check of the signature failed".into());
        }
        let t = now();
        info!("[grouter] sending item {routing_id:x} from {from} to {to}");
        self.pending.insert(
            routing_id,
            Routing {
                tunnel_hash: tunnel_hash(&to.0, CLIENT_MESSAGES),
                item_hash: item.hash(),
                item,
                receipt: None,
                status: STATUS_PENDING,
                tunnel_status: TUNNEL_UNMANAGED,
                flags: IS_ORIGIN | ALLOW_FRIENDS,
                incoming: HashSet::new(),
                received: t,
                last_sent: 0,
                last_tunnel_request: 0,
                transaction_ts: 0,
                mail: Some((mail_id, mail_sub)),
            },
        );
        self.changed = true;
        self.save();
        Ok(())
    }

    // --- every second ----------------------------------------------------------------------

    pub async fn tick(&mut self) {
        self.ticks += 1;
        let t = now();
        self.route_pending();
        self.handle_tunnels();
        if self.ticks % 10 == 0 {
            self.auto_wash();
        }
        if t > self.last_missing_check + MISSING_KEY_CHECK_EVERY && !self.missing_key.is_empty() {
            self.last_missing_check = t;
            let list = std::mem::take(&mut self.missing_key);
            for (data, route, timeout) in list {
                if timeout < t {
                    continue;
                }
                let signer = read_signature(&data.signature).map(|(id, _)| id);
                let known = match signer {
                    Some(s) => self.core.get_service_data().gxs_id().get_pub_keys_by_id(&s).await.is_some(),
                    None => false,
                };
                if known {
                    self.handle_data(data, route).await;
                } else {
                    self.missing_key.push((data, route, timeout));
                }
            }
        }
        if self.changed && t > self.last_save + 60 {
            self.save();
        }
    }

    /// p3GRouter::routePendingObjects()
    fn route_pending(&mut self) {
        let t = now();
        let friends: Vec<String> = self.connected_friends().iter().map(|p| p.to_string()).collect();
        let ids: Vec<u64> = self.pending.keys().copied().collect();
        for id in ids {
            let Some(r) = self.pending.get(&id) else { continue };
            let status = r.status;
            if status == STATUS_PENDING {
                // tunnels go straight to the destination
                let mut targets: Vec<(Route, u32)> = vec![];
                if r.flags & ALLOW_TUNNELS != 0 {
                    if let Some(tun) = self.tunnels.get(&r.tunnel_hash) {
                        if let Some(v) = tun.vpids.first() {
                            if tun.last_ok + TUNNEL_OK_WAIT_TIME <= t {
                                targets.push((Route::Tunnel(v.to_vec()), r.item.duplication));
                            }
                        }
                    }
                }
                if targets.is_empty() && r.flags & ALLOW_FRIENDS != 0 {
                    // locked_collectAvailableFriends(), without routing matrix: at random
                    let mut cands: Vec<&String> = friends
                        .iter()
                        .filter(|f| !r.incoming.contains(&Route::Friend((*f).to_owned())))
                        .collect();
                    self.rng.shuffle(&mut cands);
                    let n = cands.len().min(MAX_BRANCHING).min(r.item.duplication as usize);
                    if n > 0 {
                        let dup = r.item.duplication;
                        let each = (dup / n as u32).max(1);
                        for (i, f) in cands.into_iter().take(n).enumerate() {
                            let d = if i == 0 { (dup - each * (n as u32 - 1)).max(1) } else { each };
                            targets.push((Route::Friend(f.to_owned()), d));
                        }
                    }
                }
                if !targets.is_empty() {
                    let mut item = r.item.clone();
                    for (route, dup) in targets {
                        item.duplication = dup;
                        info!("[grouter] sending item {id:x} to {route:?}");
                        let wire = item.to_wire();
                        self.send_sliced(&route, id, &wire);
                    }
                    if let Some(r) = self.pending.get_mut(&id) {
                        r.status = STATUS_ONGOING;
                        r.transaction_ts = t;
                    }
                    self.changed = true;
                } else if let Some(r) = self.pending.get_mut(&id) {
                    if r.received + DIRECT_FRIEND_TRY_DELAY < t && r.flags & ALLOW_TUNNELS == 0 {
                        info!("[grouter] no friend for item {id:x}, allowing tunnels");
                        r.flags |= ALLOW_TUNNELS;
                    }
                }
            } else if status == STATUS_ONGOING {
                if let Some(r) = self.pending.get_mut(&id) {
                    if t > MAX_TRANSACTION_ACK_WAITING_TIME + r.transaction_ts {
                        r.status = STATUS_PENDING;
                    }
                }
            } else if status == STATUS_SENT {
                if let Some(r) = self.pending.get_mut(&id) {
                    if r.flags & IS_ORIGIN != 0 && r.last_sent + MAX_DELAY_FOR_RESEND < t {
                        r.status = STATUS_PENDING;
                    } else {
                        r.flags &= !ALLOW_TUNNELS;
                    }
                }
            }

            // receipts go back the way the item came
            let Some(r) = self.pending.get(&id) else { continue };
            if let Some(receipt) = &r.receipt {
                if r.incoming.is_empty() {
                    continue;
                }
                let wire = receipt.to_wire();
                let alive: Vec<Route> = r.incoming.iter().filter(|x| self.route_alive(x)).cloned().collect();
                for route in &alive {
                    info!("[grouter] sending the receipt of item {id:x} to {route:?}");
                    self.send_sliced(route, id, &wire);
                }
                if let Some(r) = self.pending.get_mut(&id) {
                    for route in alive {
                        r.incoming.remove(&route);
                        self.changed = true;
                    }
                    if r.incoming.is_empty() {
                        r.status = STATUS_DONE;
                    }
                }
            }
        }
    }

    /// p3GRouter::handleTunnels()
    fn handle_tunnels(&mut self) {
        let t = now();
        let mut want: HashSet<Hash> = HashSet::new();
        let mut monitor: Vec<Hash> = vec![];
        for r in self.pending.values_mut() {
            if r.status == STATUS_PENDING && r.flags & ALLOW_TUNNELS != 0 {
                if r.tunnel_status == TUNNEL_UNMANAGED && r.last_tunnel_request + MAX_TUNNEL_UNMANAGED_TIME < t {
                    monitor.push(r.tunnel_hash);
                    r.tunnel_status = TUNNEL_PENDING;
                    r.last_tunnel_request = t;
                    want.insert(r.tunnel_hash);
                } else if r.tunnel_status == TUNNEL_PENDING && r.last_tunnel_request + MAX_TUNNEL_WAIT_TIME < t {
                    r.tunnel_status = TUNNEL_UNMANAGED;
                } else if r.tunnel_status != TUNNEL_UNMANAGED {
                    want.insert(r.tunnel_hash);
                }
            } else if r.tunnel_status != TUNNEL_UNMANAGED {
                r.tunnel_status = TUNNEL_UNMANAGED;
            }
        }
        for h in monitor {
            info!("[grouter] digging tunnels to {}", hex::encode(h));
            self.actions.push(TurtleAction::Monitor(h));
        }
        // hashes nobody waits for anymore: stop digging (open tunnels stay until idle)
        for h in self.dug.drain().collect::<Vec<_>>() {
            if !want.contains(&h) {
                self.actions.push(TurtleAction::StopDigging(h));
            }
        }
        self.dug = want;
    }

    /// p3GRouter::autoWash()
    fn auto_wash(&mut self) {
        let t = now();
        let mut failed = vec![];
        self.pending.retain(|id, r| {
            let delete = match r.status {
                STATUS_DONE => r.flags & IS_DESTINATION == 0 || r.received + MAX_DESTINATION_KEEP_TIME < t,
                STATUS_RECEIPT_OK => r.received + MAX_RECEIPT_KEEP_TIME < t,
                _ => r.received + ITEM_MAX_CACHE_KEEP_TIME < t,
            };
            if delete {
                debug!("[grouter] removing item {id:x} from the cache");
                if r.status != STATUS_DONE {
                    if let Some(m) = r.mail {
                        failed.push(m);
                    }
                }
            }
            !delete
        });
        for (mail_id, sub) in failed {
            warn!("[grouter] mail {mail_id} could not be delivered in 2 days, trying again");
            crate::mail::distant_failed(mail_id, sub);
            self.changed = true;
        }
        self.pipes.retain(|_, p| p.last + MAX_INACTIVE_DATA_PIPE_DELAY >= t);
        let before = self.recent.len();
        self.recent.retain(|_, ts| *ts + MAX_DESTINATION_KEEP_TIME >= t);
        if self.recent.len() != before {
            self.changed = true;
        }
    }

    fn save(&mut self) {
        self.last_save = now();
        self.changed = false;
        let saved = SavedRef {
            permission: self.permission,
            pending: self.pending.iter().collect(),
            recent: self.recent.iter().map(|(h, t)| (hex::encode(h), *t)).collect(),
        };
        match serde_json::to_vec(&saved) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.save_file, json) {
                    warn!("[grouter] can't save {}: {e}", self.save_file.display());
                }
            }
            Err(e) => warn!("[grouter] can't save: {e}"),
        }
    }
}

#[derive(Serialize)]
struct SavedRef<'a> {
    permission: u32,
    pending: Vec<(&'a u64, &'a Routing)>,
    recent: Vec<(String, u64)>,
}

// --- the 0x0018 service: passes friends' packets to the router ---------------------------

use async_trait::async_trait;
use retroshare_compat::services::service_info::RsServiceInfo;
use tokio::task::JoinHandle;

use crate::services::Service;

pub struct GRouterService {
    rx: UnboundedReceiver<Intercom>,
}

impl GRouterService {
    pub async fn new(_core: &Arc<DataCore>, _core_tx: UnboundedSender<Intercom>, rx: UnboundedReceiver<Intercom>) -> Self {
        GRouterService { rx }
    }
}

#[async_trait]
impl Service for GRouterService {
    fn get_id(&self) -> ServiceType {
        ServiceType::GRouter
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "Global Router")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(msg) = self.rx.recv().await {
                if let Intercom::Receive(packet) = msg {
                    incoming_packet(packet);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trip() {
        let rsa = Rsa::generate(2048).unwrap();
        let public = rsa.public_key_to_der_pkcs1().unwrap();
        let private = rsa.private_key_to_der().unwrap();
        let data = b"distant mail".to_vec();
        let enc = encrypt_for(&public, &data).unwrap();
        assert_eq!(decrypt_with(&private, &enc).unwrap(), data);
    }

    #[test]
    fn data_item_round_trip() {
        let d = DataItem {
            routing_id: 0x1122334455667788,
            dest: [3; 16],
            service_id: CLIENT_MESSAGES,
            data: vec![1, 2, 3],
            signature: vec![0x00, 0x50, 0, 0, 0, 6],
            duplication: 4,
            flags: 1,
        };
        let wire = d.to_wire();
        let p = DataItem::parse(&wire[8..]).unwrap();
        assert_eq!(p.routing_id, d.routing_id);
        assert_eq!(p.data, d.data);
        assert_eq!(p.duplication, 4);
        assert_eq!(p.flags, 1);
    }
}
