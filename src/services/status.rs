//! Status service (0x0102), like libretroshare's p3StatusService: friends exchange
//! their online status (online / away / busy). We send ours to a friend as soon as
//! it talks to us and to everybody when it changes (see `DataCore::set_own_status`).
//!
//! When a friend connects we also ask for its status message (RetroShare's custom
//! state string, which belongs to the chat service), see `presence.rs`.

use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use retroshare_compat::services::{service_info::RsServiceInfo, ServiceType};
use tokio::{
    select,
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use crate::{
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::{
        intercom::{Intercom, PeerUpdate},
        DataCore,
    },
    presence::{
        chat_status_packet, status_name, status_packet, CHAT_FLAG_PRIVATE,
        CHAT_FLAG_REQUEST_CUSTOM_STATE, STATUS_SUB_TYPE,
    },
    services::Service,
};

pub struct Status {
    rx: UnboundedReceiver<Intercom>,
    core: Arc<DataCore>,
    core_tx: UnboundedSender<Intercom>,
    events: UnboundedReceiver<Intercom>,
}

impl Status {
    pub async fn new(
        core: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,
    ) -> Status {
        let (tx_events, rx_events) = unbounded_channel();
        core.events_subscribe(tx_events).await;

        Status {
            rx,
            core: core.to_owned(),
            core_tx,
            events: rx_events,
        }
    }

    fn send(&self, packet: Packet) {
        if self.core_tx.send(Intercom::Send(packet)).is_err() {
            warn!("[status] failed to send to core");
        }
    }

    fn handle_incoming(&self, packet: Packet) {
        let header: ServiceHeader = packet.header.to_owned().into();
        if header.sub_type != STATUS_SUB_TYPE {
            return debug!("[status] ignoring sub type {:#04x}", header.sub_type);
        }
        // RsStatusItem: u32 sendTime, u32 status
        let Some(b) = packet.payload.get(0..8) else {
            return warn!("[status] broken status item from {}", packet.peer_id);
        };
        let send_time = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let status = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        info!("[status] {} is {}", packet.peer_id, status_name(status));
        self.core
            .presence_set_peer_status(&packet.peer_id.to_string(), status, send_time);
    }

    /// A friend connected: tell it our status and ask for its status message.
    fn peer_seen(&self, peer: Arc<retroshare_compat::basics::SslId>) {
        let own = self.core.own_presence();
        self.send(status_packet(Some(peer.clone()), own.status));
        self.send(chat_status_packet(
            Some(peer),
            CHAT_FLAG_PRIVATE | CHAT_FLAG_REQUEST_CUSTOM_STATE,
            "",
        ));
    }
}

#[async_trait]
impl Service for Status {
    fn get_id(&self) -> ServiceType {
        ServiceType::Status
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "status")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!("[status] service started");
            loop {
                select! {
                    msg = self.rx.recv() => {
                        match msg {
                            Some(Intercom::Receive(packet)) => self.handle_incoming(packet),
                            Some(msg) => trace!("[status] unexpected message: {msg:?}"),
                            None => break,
                        }
                    }
                    event = self.events.recv() => {
                        if let Some(Intercom::PeerUpdate(PeerUpdate::Seen(loc))) = event {
                            self.peer_seen(loc);
                        }
                    }
                }
            }
        })
    }
}
