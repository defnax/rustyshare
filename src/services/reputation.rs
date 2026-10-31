//! GXS reputation service (0x0219), compatible with libretroshare's p3GxsReputation:
//! friends ask each other for the opinions changed since the last update they got
//! (`RsGxsReputationRequestItem`) and answer with `RsGxsReputationUpdateItem`s.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use retroshare_compat::{basics::SslId, services::service_info::RsServiceInfo};
use tokio::{
    select,
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
    time::{interval, Interval},
};

use crate::{
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::{
        intercom::{Intercom, PeerUpdate},
        DataCore,
    },
    reputation::opinion_from_u32,
    services::Service,
};

use ::retroshare_compat::services::ServiceType;

/// RS_PKT_SUBTYPE_GXS_REPUTATION_UPDATE_ITEM
const SUB_TYPE_UPDATE: u8 = 0x03;
/// RS_PKT_SUBTYPE_GXS_REPUTATION_REQUEST_ITEM
const SUB_TYPE_REQUEST: u8 = 0x04;
/// RS: kMaximumSetSize, opinions per update item
const MAX_SET_SIZE: usize = 100;
/// RS: kReputationRequestPeriod
const REQUEST_PERIOD: Duration = Duration::from_secs(600);

fn read_u32(data: &[u8], pos: usize) -> Option<u32> {
    data.get(pos..pos + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

pub struct Reputation {
    rx: UnboundedReceiver<Intercom>,
    core: Arc<DataCore>,
    core_tx: UnboundedSender<Intercom>,
    events: UnboundedReceiver<Intercom>,
    timer_request: Interval,
    timer_save: Interval,
}

impl Reputation {
    pub async fn new(
        core: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,
    ) -> Reputation {
        let (tx_events, rx_events) = unbounded_channel();
        core.events_subscribe(tx_events).await;

        Reputation {
            rx,
            core: core.to_owned(),
            core_tx,
            events: rx_events,
            timer_request: interval(REQUEST_PERIOD),
            timer_save: interval(Duration::from_secs(61)),
        }
    }

    fn send(&self, sub_type: u8, payload: Vec<u8>, peer: Arc<SslId>) {
        let header = ServiceHeader::new(self.get_id(), sub_type, &payload);
        let packet = Packet::new(header.into(), payload, peer);
        if self.core_tx.send(Intercom::Send(packet)).is_err() {
            warn!("[reputation] failed to send to core");
        }
    }

    /// `sendReputationRequest()`: ask for opinions newer than what we have.
    fn send_request(&self, peer: Arc<SslId>) {
        let last = self.core.reputation_peer_latest(&peer.to_string());
        debug!("[reputation] asking {peer} for opinions since {last}");
        self.send(SUB_TYPE_REQUEST, last.to_be_bytes().to_vec(), peer);
    }

    /// `SendReputations()`: our opinions changed since the friend's last update.
    fn handle_request(&self, peer: Arc<SslId>, payload: &[u8]) {
        let Some(since) = read_u32(payload, 0) else {
            return warn!("[reputation] broken request from {peer}");
        };
        let updates = self.core.reputation_own_updates_since(since);
        if updates.is_empty() {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or_default();
        debug!("[reputation] sending {} opinions to {peer}", updates.len());

        for chunk in updates.chunks(MAX_SET_SIZE) {
            let mut latest = chunk.last().map(|(_, _, ts)| *ts).unwrap_or_default();
            if latest == now {
                latest -= 1; // like RetroShare: don't miss opinions set in this second
            }
            // u32 latest update, std::map<RsGxsId, uint32_t>: u32 count, (16 bytes id, u32)
            let mut payload = latest.to_be_bytes().to_vec();
            payload.extend((chunk.len() as u32).to_be_bytes());
            for (id, op, _) in chunk {
                match hex::decode(id) {
                    Ok(bytes) if bytes.len() == 16 => payload.extend(bytes),
                    _ => continue,
                }
                payload.extend((*op as u32).to_be_bytes());
            }
            self.send(SUB_TYPE_UPDATE, payload, peer.clone());
        }
    }

    /// `RecvReputations()`
    fn handle_update(&self, peer: Arc<SslId>, payload: &[u8]) {
        let (Some(latest), Some(count)) = (read_u32(payload, 0), read_u32(payload, 4)) else {
            return warn!("[reputation] broken update from {peer}");
        };
        let mut opinions = vec![];
        let mut pos = 8;
        for _ in 0..count {
            let (Some(id), Some(op)) = (payload.get(pos..pos + 16), read_u32(payload, pos + 16))
            else {
                return warn!("[reputation] truncated update from {peer}");
            };
            opinions.push((hex::encode(id), opinion_from_u32(op)));
            pos += 20;
        }
        debug!("[reputation] {} opinions from {peer}", opinions.len());
        self.core
            .reputation_apply_friend_update(&peer.to_string(), &opinions, latest);
    }

    fn handle_incoming(&self, packet: Packet) {
        let header: ServiceHeader = packet.header.to_owned().into();
        match header.sub_type {
            SUB_TYPE_REQUEST => self.handle_request(packet.peer_id.clone(), &packet.payload),
            SUB_TYPE_UPDATE => self.handle_update(packet.peer_id.clone(), &packet.payload),
            other => debug!("[reputation] ignoring sub type {other:#04x}"),
        }
    }
}

#[async_trait]
impl Service for Reputation {
    fn get_id(&self) -> ServiceType {
        ServiceType::Reputation
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "gxsreputation")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!("[reputation] service started");
            loop {
                select! {
                    msg = self.rx.recv() => {
                        match msg {
                            Some(Intercom::Receive(packet)) => self.handle_incoming(packet),
                            Some(msg) => trace!("[reputation] unexpected message: {msg:?}"),
                            None => break,
                        }
                    }
                    event = self.events.recv() => {
                        // ask a friend as soon as it really talks to us
                        if let Some(Intercom::PeerUpdate(PeerUpdate::Seen(loc))) = event {
                            self.send_request(loc);
                        }
                    }
                    _ = self.timer_request.tick() => {
                        let peers: Vec<_> = self.core.get_connected_peers().lock().await.0.keys().cloned().collect();
                        for peer in peers {
                            self.send_request(peer);
                        }
                    }
                    _ = self.timer_save.tick() => {
                        self.core.reputation_save(false);
                    }
                }
            }
        })
    }
}
