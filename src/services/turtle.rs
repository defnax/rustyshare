//! Turtle router (service 0x0014), like libretroshare's `turtle/p3turtle.cc`:
//! - forwards tunnel requests, tunnel answers and tunnel data of others
//! - digs own tunnels (for GXS tunnels / distant chat) and answers tunnel requests
//!   for our own identities; the data of tunnels ending here goes to `gxs_tunnel.rs`
//!
//! Tunnel ids like RetroShare: the requester sends a "partial tunnel id" made from the
//! hash and its location id, the answering side xors in its own part. Virtual peer id
//! of a tunnel ending here: the tunnel id (big endian) followed by 12 zero bytes.

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use nanorand::{Rng, WyRand};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
    time::{interval, Interval},
};

use retroshare_compat::{
    basics::{Sha1CheckSum, SslId},
    serde::{from_retroshare_wire_result, to_retroshare_wire},
    services::{service_info::RsServiceInfo, turtle::*},
};

use crate::{
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::{intercom::Intercom, DataCore},
    services::{
        gxs_tunnel::{GxsTunnels, Hash, TunnelCmd, TurtleAction, Vpid},
        Service,
    },
};

use ::retroshare_compat::services::ServiceType;

const TURTLE_SUB_TYPE_STRING_SEARCH_REQUEST: u8 = 0x01;
const TURTLE_SUB_TYPE_FT_SEARCH_RESULT: u8 = 0x02;
const TURTLE_SUB_TYPE_OPEN_TUNNEL: u8 = 0x03;
const TURTLE_SUB_TYPE_TUNNEL_OK: u8 = 0x04;
const TURTLE_SUB_TYPE_FILE_REQUEST: u8 = 0x07;
const TURTLE_SUB_TYPE_FILE_DATA: u8 = 0x08;
const TURTLE_SUB_TYPE_REGEXP_SEARCH_REQUEST: u8 = 0x09;
const TURTLE_SUB_TYPE_GENERIC_DATA: u8 = 0x0a;
const TURTLE_SUB_TYPE_GENERIC_SEARCH_REQUEST: u8 = 0x0b;
const TURTLE_SUB_TYPE_GENERIC_SEARCH_RESULT: u8 = 0x0c;
const TURTLE_SUB_TYPE_FILE_MAP: u8 = 0x10;
const TURTLE_SUB_TYPE_FILE_MAP_REQUEST: u8 = 0x11;
const TURTLE_SUB_TYPE_FILE_CRC: u8 = 0x12; // unused
const TURTLE_SUB_TYPE_FILE_CRC_REQUEST: u8 = 0x13; // unused
const TURTLE_SUB_TYPE_CHUNK_CRC: u8 = 0x14;
const TURTLE_SUB_TYPE_CHUNK_CRC_REQUEST: u8 = 0x15;
const TURTLE_SUB_TYPE_GENERIC_FAST_DATA: u8 = 0x16;

/// life time for tunnel requests in the cache.
const TUNNEL_REQUESTS_LIFE_TIME: Duration = Duration::from_secs(600);
/// maximum time during which we process/forward results for known tunnel requests
const TUNNEL_REQUESTS_RESULT_TIME: Duration = Duration::from_secs(20);
/// maximum life time of an unused tunnel.
const MAXIMUM_TUNNEL_IDLE_TIME: Duration = Duration::from_secs(60);
/// own hashes without tunnel: dig again after this time
const EMPTY_TUNNELS_DIGGING_TIME: Duration = Duration::from_secs(50);
/// TURTLE_MAX_SEARCH_DEPTH
const MAX_DEPTH: u16 = 6;

/// One end of a tunnel: a friend, or we.
#[derive(Debug, Clone, PartialEq)]
enum End {
    Own,
    Peer(Arc<SslId>),
}

#[derive(Debug)]
struct TunnelRequest {
    /// who sent it to us (Own: we dug it)
    from: End,
    time: Instant,
    /// tunnel ids we got back for it
    responses: HashSet<u32>,
}

#[derive(Debug)]
struct Tunnel {
    /// side of the requester
    src: End,
    /// side of the answer
    dst: End,
    last_active: Instant,
    /// tunnels starting or ending here
    hash: Option<Hash>,
    vpid: Option<Vpid>,
}

/// An own hash we dig tunnels for (TurtleHashInfo).
struct HashInfo {
    tunnels: Vec<u32>,
    last_request: u32,
    last_digg: Option<Instant>,
    /// dig again at the next chance (forceReDiggTunnels)
    force: bool,
}

pub struct Turtle {
    rx: UnboundedReceiver<Intercom>,
    core: Arc<DataCore>,
    core_tx: UnboundedSender<Intercom>,

    rng: WyRand,
    own_id: Arc<SslId>,
    random_bias: u32,

    requests: HashMap<u32, TunnelRequest>,
    tunnels: HashMap<u32, Tunnel>,
    monitored: HashMap<Hash, HashInfo>,
    virtual_peers: HashMap<Vpid, u32>,

    gxs: GxsTunnels,
    cmd_rx: UnboundedReceiver<TunnelCmd>,

    timer_maintenance: Interval,
    timer_second: Interval,
}

impl Turtle {
    pub async fn new(
        core: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,
    ) -> Turtle {
        let mut rng = WyRand::new();
        let random_bias = rng.generate::<u32>();
        let (gxs, cmd_rx) = GxsTunnels::new(core, core_tx.clone()).await;
        Turtle {
            rx,
            core: core.clone(),
            core_tx,

            rng,
            own_id: core.get_own_location().get_location_id(),
            random_bias,

            requests: HashMap::new(),
            tunnels: HashMap::new(),
            monitored: HashMap::new(),
            virtual_peers: HashMap::new(),

            gxs,
            cmd_rx,

            timer_maintenance: interval(Duration::from_secs(10)),
            timer_second: interval(Duration::from_secs(1)),
        }
    }

    fn send(&self, sub_type: u8, payload: Vec<u8>, to: Arc<SslId>) {
        let header = ServiceHeader::new(ServiceType::Turtle, sub_type, &payload);
        let _ = self.core_tx.send(Intercom::Send(Packet::new(header.into(), payload, to)));
    }

    fn connected_peers(&self) -> Vec<Arc<SslId>> {
        self.core
            .get_locations()
            .iter()
            .filter(|l| l.is_connected())
            .map(|l| l.get_location_id())
            .collect()
    }

    /// p3turtle::generatePersonalFilePrint()
    fn personal_print(&self, hash: &Hash, seed: u32, b: bool) -> u32 {
        let buff = hex::encode(hash) + &self.own_id.to_string();
        let mut res = seed;
        let mut decal: u32 = 0;
        for c in buff.bytes() {
            res = res.wrapping_add(7u32.wrapping_mul(c as u32)).wrapping_add(decal);
            decal = if b {
                decal.wrapping_mul(44497).wrapping_add(15641).wrapping_add(res % 86243)
            } else {
                decal.wrapping_mul(86243).wrapping_add(15649).wrapping_add(res % 44497)
            };
        }
        res
    }

    async fn handle_incoming(&mut self, header: &ServiceHeader, mut packet: Packet) {
        trace!("handle_incoming: {header:?}");
        match header.sub_type {
            TURTLE_SUB_TYPE_STRING_SEARCH_REQUEST => {
                if let Ok(item) = from_retroshare_wire_result::<TurtleStringSearchRequestItem>(&mut packet.payload) {
                    trace!("search request: string: {item:?}");
                }
            }
            TURTLE_SUB_TYPE_OPEN_TUNNEL => self.handle_open_tunnel(packet).await,
            TURTLE_SUB_TYPE_TUNNEL_OK => self.handle_tunnel_ok(packet).await,
            TURTLE_SUB_TYPE_GENERIC_DATA => self.handle_generic_data(packet, false).await,
            TURTLE_SUB_TYPE_GENERIC_FAST_DATA => self.handle_generic_data(packet, true).await,
            TURTLE_SUB_TYPE_REGEXP_SEARCH_REQUEST | TURTLE_SUB_TYPE_GENERIC_SEARCH_REQUEST => {
                trace!("search request {:#x} (no file sharing yet)", header.sub_type)
            }
            TURTLE_SUB_TYPE_FT_SEARCH_RESULT
            | TURTLE_SUB_TYPE_FILE_REQUEST
            | TURTLE_SUB_TYPE_FILE_DATA
            | TURTLE_SUB_TYPE_GENERIC_SEARCH_RESULT
            | TURTLE_SUB_TYPE_FILE_MAP
            | TURTLE_SUB_TYPE_FILE_MAP_REQUEST
            | TURTLE_SUB_TYPE_CHUNK_CRC
            | TURTLE_SUB_TYPE_CHUNK_CRC_REQUEST => {}
            TURTLE_SUB_TYPE_FILE_CRC | TURTLE_SUB_TYPE_FILE_CRC_REQUEST => {
                debug!("{} should not be used (sent by {})", header.sub_type, packet.peer_id);
            }
            sub_type => debug!("received unknown sub type {sub_type}"),
        }
    }

    /// p3turtle::handleTunnelRequest()
    async fn handle_open_tunnel(&mut self, mut packet: Packet) {
        let Ok(item) = from_retroshare_wire_result::<TurtleOpenTunnelItem>(&mut packet.payload) else {
            return debug!("broken tunnel request from {}", packet.peer_id);
        };
        self.open_tunnel_request(item, End::Peer(packet.peer_id.clone())).await;
    }

    async fn open_tunnel_request(&mut self, mut item: TurtleOpenTunnelItem, from: End) {
        // bounce check
        if self.requests.contains_key(&item.request_id) {
            trace!("dropping bounced tunnel request {item}");
            return;
        }
        let own = from == End::Own;
        self.requests.insert(
            item.request_id,
            TunnelRequest { from: from.clone(), time: Instant::now(), responses: HashSet::new() },
        );

        // for us? (performLocalHashSearch: GXS tunnels to our identities)
        let hash: Hash = item.file_hash.0;
        if let End::Peer(peer) = &from {
            if self.gxs.handle_tunnel_request(&hash) {
                let tunnel_id = item.partial_tunnel_id ^ self.personal_print(&hash, self.random_bias, false);
                let ok = TurtleTunnelOkItem { tunnel_id, request_id: item.request_id };
                self.send(TURTLE_SUB_TYPE_TUNNEL_OK, to_retroshare_wire(&ok), peer.clone());
                let vpid = vpid_of(tunnel_id);
                self.tunnels.insert(
                    tunnel_id,
                    Tunnel { src: from.clone(), dst: End::Own, last_active: Instant::now(), hash: Some(hash), vpid: Some(vpid) },
                );
                self.virtual_peers.insert(vpid, tunnel_id);
                info!("tunnel {tunnel_id:08x} to one of our identities opened");
                self.gxs.add_virtual_peer(hash, vpid, false).await;
                self.run_actions().await;
                return;
            }
        }

        // forwarding by probability (keeps tunnels short, see forward());
        // own requests always go out
        if item.depth >= MAX_DEPTH || (!own && !self.forward()) {
            trace!("not forwarding tunnel request {item}");
            return;
        }
        // multi tunnel trick of RetroShare: a different half tunnel id per route
        item.partial_tunnel_id = self.personal_print(&hash, item.partial_tunnel_id ^ self.random_bias, true);
        if !own {
            item.depth += 1;
        }
        let payload = to_retroshare_wire(&item);
        let mut sent = 0;
        for peer in self.connected_peers() {
            if End::Peer(peer.clone()) == from {
                continue;
            }
            self.send(TURTLE_SUB_TYPE_OPEN_TUNNEL, payload.clone(), peer);
            sent += 1;
        }
        if own {
            debug!("digging tunnel {:08x} for {} through {sent} friends", item.request_id, hex::encode(hash));
        }
    }

    /// p3turtle::handleTunnelResult()
    async fn handle_tunnel_ok(&mut self, mut packet: Packet) {
        let Ok(item) = from_retroshare_wire_result::<TurtleTunnelOkItem>(&mut packet.payload) else {
            return debug!("broken tunnel ok from {}", packet.peer_id);
        };
        let Some(request) = self.requests.get_mut(&item.request_id) else {
            return trace!("no pending tunnel request for {:08x}", item.request_id);
        };
        if !request.responses.insert(item.tunnel_id) {
            return; // seen this answer before
        }
        if request.time.elapsed() > TUNNEL_REQUESTS_RESULT_TIME {
            return trace!("answer for tunnel request {:08x} came too late", item.request_id);
        }
        let origin = request.from.clone();
        let tunnel = self.tunnels.entry(item.tunnel_id).or_insert_with(|| Tunnel {
            src: origin.clone(),
            dst: End::Peer(packet.peer_id.clone()),
            last_active: Instant::now(),
            hash: None,
            vpid: None,
        });
        tunnel.last_active = Instant::now();

        match origin {
            End::Peer(origin) => {
                // not ours: send it back where the request came from
                let payload = to_retroshare_wire(&item);
                self.send(TURTLE_SUB_TYPE_TUNNEL_OK, payload, origin);
            }
            End::Own => {
                // one of our own requests: a new tunnel for that hash
                let Some((hash, info)) =
                    self.monitored.iter_mut().find(|(_, h)| h.last_request == item.request_id)
                else {
                    return debug!("tunnel ok for an own request of a hash we don't dig anymore");
                };
                let hash = *hash;
                if !info.tunnels.contains(&item.tunnel_id) {
                    info.tunnels.push(item.tunnel_id);
                }
                let vpid = vpid_of(item.tunnel_id);
                if let Some(t) = self.tunnels.get_mut(&item.tunnel_id) {
                    t.hash = Some(hash);
                    t.vpid = Some(vpid);
                }
                self.virtual_peers.insert(vpid, item.tunnel_id);
                info!("tunnel {:08x} for {} is there", item.tunnel_id, hex::encode(hash));
                self.gxs.add_virtual_peer(hash, vpid, true).await;
                self.run_actions().await;
            }
        }
    }

    /// p3turtle::routeGenericTunnelItem(): generic data (0x0a) and fast data (0x16),
    /// both `u32 tunnel id, u32 size, data`
    async fn handle_generic_data(&mut self, mut packet: Packet, fast: bool) {
        let p = &packet.payload;
        if p.len() < 8 {
            return;
        }
        let tunnel_id = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
        let Some(tunnel) = self.tunnels.get_mut(&tunnel_id) else {
            return trace!("no tunnel {tunnel_id:08x}");
        };
        let from = End::Peer(packet.peer_id.clone());
        let to = if from == tunnel.dst {
            tunnel.src.clone()
        } else if from == tunnel.src {
            tunnel.dst.clone()
        } else {
            debug!("data for tunnel {tunnel_id:08x} from a wrong friend, dropping the tunnel");
            self.tunnels.remove(&tunnel_id);
            return;
        };
        tunnel.last_active = Instant::now();
        match to {
            End::Peer(peer) => {
                // forward unchanged
                packet.peer_id = peer;
                let _ = self.core_tx.send(Intercom::Send(packet));
            }
            End::Own => {
                let size = u32::from_be_bytes([p[4], p[5], p[6], p[7]]) as usize;
                let Some(data) = p.get(8..8 + size).map(|d| d.to_vec()) else { return };
                let Some(vpid) = tunnel.vpid else { return };
                self.gxs.receive_turtle_data(vpid, &data, fast).await;
                self.run_actions().await;
            }
        }
    }

    /// p3turtle::sendTurtleData()
    fn send_data(&mut self, vpid: &Vpid, data: Vec<u8>, fast: bool) {
        let Some(tunnel_id) = self.virtual_peers.get(vpid).copied() else {
            return debug!("no tunnel for virtual peer {}", hex::encode(vpid));
        };
        let Some(tunnel) = self.tunnels.get_mut(&tunnel_id) else { return };
        tunnel.last_active = Instant::now();
        let to = match (&tunnel.src, &tunnel.dst) {
            (End::Own, End::Peer(p)) | (End::Peer(p), End::Own) => p.clone(),
            _ => return,
        };
        let mut payload = tunnel_id.to_be_bytes().to_vec();
        payload.extend((data.len() as u32).to_be_bytes());
        payload.extend(data);
        let sub = if fast { TURTLE_SUB_TYPE_GENERIC_FAST_DATA } else { TURTLE_SUB_TYPE_GENERIC_DATA };
        self.send(sub, payload, to);
    }

    /// What the GXS tunnels asked for.
    async fn run_actions(&mut self) {
        for action in self.gxs.take_actions() {
            match action {
                TurtleAction::Send { vpid, data, fast } => self.send_data(&vpid, data, fast),
                TurtleAction::Monitor(hash) => {
                    // p3turtle::monitorTunnels(): first digging soon
                    self.monitored.entry(hash).or_insert(HashInfo { tunnels: vec![], last_request: 0, last_digg: None, force: false });
                }
                TurtleAction::StopMonitor(hash) => {
                    if let Some(info) = self.monitored.remove(&hash) {
                        for t in info.tunnels {
                            self.close_tunnel(t);
                        }
                    }
                }
                TurtleAction::Redigg(hash) => {
                    if let Some(info) = self.monitored.get_mut(&hash) {
                        info.force = true;
                    }
                }
            }
        }
    }

    /// p3turtle::diggTunnel()
    async fn dig(&mut self, hash: Hash) {
        let request_id = self.rng.generate::<u32>();
        if let Some(info) = self.monitored.get_mut(&hash) {
            info.last_request = request_id;
            info.last_digg = Some(Instant::now());
            info.force = false;
        }
        let item = TurtleOpenTunnelItem {
            file_hash: Sha1CheckSum(hash),
            request_id,
            partial_tunnel_id: self.personal_print(&hash, self.random_bias, true),
            depth: 0,
        };
        self.open_tunnel_request(item, End::Own).await;
    }

    /// p3turtle::manageTunnels(): every second, at most one own hash without tunnel
    async fn manage_tunnels(&mut self) {
        let due = self
            .monitored
            .iter()
            .filter(|(_, h)| {
                h.force
                    || (h.tunnels.is_empty()
                        && h.last_digg.map(|t| t.elapsed() >= EMPTY_TUNNELS_DIGGING_TIME).unwrap_or(true))
            })
            .min_by_key(|(_, h)| h.last_digg)
            .map(|(hash, _)| *hash);
        if let Some(hash) = due {
            self.dig(hash).await;
        }
    }

    /// p3turtle::locked_closeTunnel()
    fn close_tunnel(&mut self, tunnel_id: u32) {
        let Some(t) = self.tunnels.remove(&tunnel_id) else { return };
        if let Some(vpid) = t.vpid {
            self.virtual_peers.remove(&vpid);
            self.gxs.remove_virtual_peer(&vpid);
        }
        if let Some(hash) = t.hash {
            if let Some(info) = self.monitored.get_mut(&hash) {
                info.tunnels.retain(|x| *x != tunnel_id);
            }
        }
    }

    /// p3turtle::autoWash(): old requests and unused tunnels
    fn auto_wash(&mut self) {
        self.requests.retain(|_, r| r.time.elapsed() < TUNNEL_REQUESTS_LIFE_TIME);
        let connected: HashSet<Arc<SslId>> = self.connected_peers().into_iter().collect();
        let old: Vec<u32> = self
            .tunnels
            .iter()
            .filter(|(_, t)| {
                let gone = |e: &End| matches!(e, End::Peer(p) if !connected.contains(p));
                t.last_active.elapsed() > MAXIMUM_TUNNEL_IDLE_TIME || gone(&t.src) || gone(&t.dst)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in old {
            trace!("closing tunnel {id:08x}");
            self.close_tunnel(id);
        }
    }

    fn forward(&mut self) -> bool {
        // Goal: tunnel should usually not exceed 6 hops
        // - drop probability: x
        // - (1-x)^6 <= (1-0.9) drop probability after 6 hop >= 90%
        // - x ~ 0.33 results in about 9% chance of a tunnel being longer than 6 hops
        self.rng.generate_range(0..100) > 66
    }
}

/// p3turtle::locked_addDistantPeer(): the tunnel id, then zeros
fn vpid_of(tunnel_id: u32) -> Vpid {
    let mut v = [0u8; 16];
    v[..4].copy_from_slice(&tunnel_id.to_be_bytes());
    v
}

#[async_trait]
impl Service for Turtle {
    fn get_id(&self) -> ServiceType {
        ServiceType::Turtle
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "turtle")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticks: u64 = 0;
            loop {
                select! {
                    msg = self.rx.recv() => {
                        match msg {
                            Some(Intercom::Receive(packet)) => {
                                let _t = crate::watchdog::time("turtle.packet");
                                let header: ServiceHeader = packet.header.to_owned().into();
                                self.handle_incoming(&header, packet).await;
                            }
                            Some(msg) => warn!("unexpected message: {msg:?}"),
                            None => break, // channel closed: stop instead of spinning
                        }
                    }
                    cmd = self.cmd_rx.recv() => {
                        if let Some(cmd) = cmd {
                            self.gxs.handle_cmd(cmd).await;
                            self.run_actions().await;
                        }
                    }
                    _ = self.timer_second.tick() => {
                        let _t = crate::watchdog::time("turtle.tick");
                        ticks += 1;
                        self.manage_tunnels().await;
                        self.gxs.tick();
                        if ticks % 30 == 1 {
                            self.gxs.refresh_names().await;
                        }
                        self.run_actions().await;
                    }
                    _ = self.timer_maintenance.tick() => {
                        self.auto_wash();
                        self.run_actions().await;
                    }
                }
            }
        })
    }
}
