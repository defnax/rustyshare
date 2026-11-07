//! Mail service (0x0013, "msg"), like libretroshare's p3MsgService for mail between friends:
//! - incoming `RsMsgItem`s are stored in the inbox (flags reduced to DISTANT / SYSTEM,
//!   NEW set, a new message id); long mails arrive in parts (`RS_MSG_FLAGS_PARTIAL`)
//! - the outbox has one entry per destination; an entry is sent as soon as that friend
//!   is connected, bcc removed, mails longer than 15000 bytes in parts; when all
//!   destinations got it, the sent mail is no longer pending
//!
//! The mailbox itself is in `mail.rs`.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use log::{info, trace, warn};
use retroshare_compat::{
    basics::SslId,
    services::{service_info::RsServiceInfo, ServiceType},
};
use tokio::{
    select,
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
    time::{interval, Duration},
};

use crate::{
    low_level_parsing::{headers::ServiceHeader, Packet},
    mail::{self, flags, Address, Mail, MsgItem},
    model::{
        intercom::{Intercom, PeerUpdate},
        DataCore,
    },
    services::Service,
};

/// p3MsgService::checkSizeAndSendMessage(): MAX_STRING_SIZE
const MAX_PART: usize = 15000;

pub struct MailService {
    rx: UnboundedReceiver<Intercom>,
    core: Arc<DataCore>,
    core_tx: UnboundedSender<Intercom>,
    events: UnboundedReceiver<Intercom>,
    /// parts of long mails, per friend
    partial: HashMap<String, MsgItem>,
}

fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or_default()
}

impl MailService {
    pub async fn new(
        core: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,
    ) -> MailService {
        let (tx_events, rx_events) = unbounded_channel();
        core.events_subscribe(tx_events).await;
        MailService {
            rx,
            core: core.to_owned(),
            core_tx,
            events: rx_events,
            partial: HashMap::new(),
        }
    }

    fn handle_incoming(&mut self, packet: Packet) {
        let header: ServiceHeader = packet.header.to_owned().into();
        if header.sub_type != mail::SUBTYPE_MSG {
            return trace!("[mail] ignoring sub type {:#04x}", header.sub_type);
        }
        let Some(mut msg) = mail::parse_wire_msg(&packet.payload) else {
            return warn!("[mail] broken mail item from {}", packet.peer_id);
        };
        let peer = packet.peer_id.to_string();

        // p3MsgService::checkAndRebuildPartialMessage()
        if let Some(first) = self.partial.remove(&peer) {
            msg.message = first.message + &msg.message;
            msg.flags |= first.flags;
        }
        if msg.flags & flags::PARTIAL != 0 {
            self.partial.insert(peer, msg);
            return;
        }

        // p3MsgService::processIncomingMsg()
        let own = self.core.get_own_location().get_location_id().to_string();
        let Some(mut store) = mail::store() else { return };
        msg.recv_time = now();
        msg.msg_id = store.new_id();
        msg.flags &= flags::DISTANT | flags::SYSTEM;
        msg.flags |= flags::NEW;
        info!("[mail] new mail from {peer}: {:?}", msg.subject);
        let id = msg.msg_id;
        store.mails.insert(
            id,
            Mail {
                from: Address::peer(&peer, 1),
                to: Address::peer(&own, 1),
                msg,
                ..Default::default()
            },
        );
        store.save();
    }

    /// p3MsgService::checkOutgoingMessages(): sends what waits for connected friends.
    async fn check_outbox(&self) {
        let connected: HashMap<String, Arc<SslId>> = self
            .core
            .get_connected_peers()
            .lock()
            .await
            .0
            .keys()
            .map(|p| (p.to_string(), p.to_owned()))
            .collect();
        let own = self.core.get_own_location().get_location_id();
        let own_hex = own.to_string();

        let mut packets = vec![];
        let mut local = vec![];
        {
            let Some(mut store) = mail::store() else { return };
            if store.outgoing.is_empty() {
                return;
            }
            let mut changed = false;
            let ids: Vec<u32> = store.outgoing.keys().copied().collect();
            for id in ids {
                let Some(source) = store.mails.get(&id).cloned() else {
                    warn!("[mail] outgoing mail {id} has no stored copy, dropping it");
                    store.outgoing.remove(&id);
                    changed = true;
                    continue;
                };
                let copies = store.outgoing.get(&id).cloned().unwrap_or_default();
                for (sub, info) in copies {
                    if info.destination.ty != Address::TYPE_PEER {
                        continue; // distant mail needs GXS tunnels, not yet
                    }
                    let to = info.destination.addr.to_lowercase();
                    let target = if to == own_hex {
                        None
                    } else if let Some(peer) = connected.get(&to) {
                        Some(peer.to_owned())
                    } else {
                        continue; // friend offline: stays in the outbox
                    };
                    // createOutgoingMessageItem(): bcc removed (except ourselves)
                    let mut item = source.msg.clone();
                    item.peers_bcc.retain(|p| hex::encode(p) == own_hex);
                    item.gxs_bcc.clear();
                    match target {
                        Some(peer) => {
                            info!("[mail] sending {:?} to {to}", item.subject);
                            packets.extend(split_packets(&item, peer));
                        }
                        None => local.push(item),
                    }
                    if let Some(c) = store.outgoing.get_mut(&id) {
                        c.remove(&sub);
                    }
                    changed = true;
                }
                if store.outgoing.get(&id).map(|c| c.is_empty()).unwrap_or(false) {
                    store.outgoing.remove(&id);
                    if let Some(m) = store.mails.get_mut(&id) {
                        m.msg.flags &= !flags::PENDING;
                    }
                }
            }
            // a mail to ourselves arrives in our own inbox
            for mut msg in local {
                msg.recv_time = now();
                msg.msg_id = store.new_id();
                msg.flags &= flags::DISTANT | flags::SYSTEM;
                msg.flags |= flags::NEW;
                store.mails.insert(
                    msg.msg_id,
                    Mail { from: Address::peer(&own_hex, 1), to: Address::peer(&own_hex, 1), msg, ..Default::default() },
                );
            }
            if changed {
                store.save();
            }
        }
        for packet in packets {
            if self.core_tx.send(Intercom::Send(packet)).is_err() {
                warn!("[mail] failed to send to core");
            }
        }
    }
}

/// The item, split like p3MsgService::checkSizeAndSendMessage() when it is long.
fn split_packets(item: &MsgItem, peer: Arc<SslId>) -> Vec<Packet> {
    let mut parts = vec![];
    let mut rest = item.message.as_str();
    while rest.len() > MAX_PART {
        // cut at a character boundary
        let mut cut = MAX_PART;
        while !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        let mut part = item.clone();
        part.message = rest[..cut].to_owned();
        part.flags |= flags::PARTIAL;
        parts.push(part);
        rest = &rest[cut..];
    }
    let mut last = item.clone();
    last.message = rest.to_owned();
    parts.push(last);

    parts
        .into_iter()
        .map(|m| {
            let mut payload = vec![];
            mail::write_msg(&mut payload, &m, false);
            let header = ServiceHeader::new(ServiceType::Mail, mail::SUBTYPE_MSG, &payload);
            Packet::new(header.into(), payload, peer.clone())
        })
        .collect()
}

#[async_trait]
impl Service for MailService {
    fn get_id(&self) -> ServiceType {
        ServiceType::Mail
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "msg")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!("[mail] service started");
            let mut timer = interval(Duration::from_secs(30));
            loop {
                select! {
                    msg = self.rx.recv() => {
                        match msg {
                            Some(Intercom::Receive(packet)) => self.handle_incoming(packet),
                            Some(msg) => trace!("[mail] unexpected message: {msg:?}"),
                            None => break,
                        }
                    }
                    event = self.events.recv() => {
                        // a friend connected: send what waits for it (statusChange())
                        if let Some(Intercom::PeerUpdate(PeerUpdate::Seen(_))) = event {
                            self.check_outbox().await;
                        }
                    }
                    _ = mail::outbox_wait() => self.check_outbox().await,
                    _ = timer.tick() => self.check_outbox().await,
                }
            }
        })
    }
}
