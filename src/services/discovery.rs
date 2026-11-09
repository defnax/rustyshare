use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use retroshare_compat::{
    basics::{GxsId, SslId},
    gxs::sqlite::types::SubscribeFlags,
    serde::{from_retroshare_wire, to_retroshare_wire},
    services::{discovery::*, service_info::RsServiceInfo},
    tlv::{
        tlv_ip_addr::{TlvIpAddrSet, TlvIpAddress},
        tlv_set::TlvPgpIdSet,
    },
};
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
    send_to_core,
    services::Service,
};

use ::retroshare_compat::services::ServiceType;

const DISCOVERY_SUB_TYPE_PGP_LIST: u8 = 0x01;
const DISCOVERY_SUB_TYPE_PGP_CERT: u8 = 0x02;
#[deprecated]
const DISCOVERY_SUB_TYPE_CONTACT: u8 = 0x05;
const DISCOVERY_SUB_TYPE_IDENTITY_LIST: u8 = 0x06;
const DISCOVERY_SUB_TYPE_PGP_CERT_BINARY: u8 = 0x09;

pub struct Discovery {
    rx: UnboundedReceiver<Intercom>,

    own_id: Arc<SslId>,

    core_tx: UnboundedSender<Intercom>,
    events_rx: UnboundedReceiver<Intercom>,

    core: Arc<DataCore>,

    /// friends to send our contact info to, a moment after they talked to us
    delayed_tx: UnboundedSender<Arc<SslId>>,
    delayed_rx: UnboundedReceiver<Arc<SslId>>,
}

/// RetroShare drops items of a service until it has processed our service list
/// (p3ServiceControl), so wait a bit after the friend's first packet.
const CONTACT_INFO_DELAY: std::time::Duration = std::time::Duration::from_secs(3);

impl Discovery {
    pub async fn new(
        core: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,
    ) -> Discovery {
        let (tx_events, rx_events) = unbounded_channel();
        core.events_subscribe(tx_events).await;
        let (delayed_tx, delayed_rx) = unbounded_channel();

        let d = Discovery {
            delayed_tx,
            delayed_rx,
            rx,

            own_id: core.get_own_location().get_location_id().clone(),

            core_tx,
            events_rx: rx_events,

            core: core.clone(),
        };
        d
    }

    /// Our current contact info (real location name and addresses from peers.cfg).
    async fn own_info(&self) -> DiscContactItem {
        let mut info = DiscContactItem::default();
        let own = self.core.get_own_location();
        info.pgp_id = own.get_person().get_pgp_id().clone();
        info.ssl_id = *self.own_id;
        info.version = format!("rustyshare {}", env!("CARGO_PKG_VERSION")).into();
        info.location = own.get_name().to_owned().into();
        // rustyshare has no DHT yet
        info.vs_dht = VsDht::Off as u16;

        let item = self.core.get_own_peers_cfg_item().await;
        // discovery setting of the Network page (peers.cfg vs_disc, like RetroShare)
        info.vs_disc = item.as_ref().map(|i| i.vs_disc).unwrap_or(VsDisc::Full as u16);
        let local = item.as_ref().map(|i| i.local_addr_v4.to_owned()).filter(|a| a.0.port() != 0);
        let ext = item
            .as_ref()
            .map(|i| i.ext_addr_v4.to_owned())
            .filter(|a| a.0.port() != 0 && crate::upnp::is_public_ip(&a.0.ip()));
        // RS_NET_MODE_EXT (0x1) when we know our external address, else RS_NET_MODE_UDP (0x4)
        info.net_mode = if ext.is_some() { 0x1 } else { 0x4 };

        let entry = |addr: &TlvIpAddress| -> retroshare_compat::tlv::tlv_ip_addr::TlvIpAddressInfo {
            retroshare_compat::tlv::tlv_ip_addr::TlvIpAddressInfoInner {
                addr: addr.to_owned(),
                seen_time: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                source: 0,
            }
            .into()
        };
        info.local_addr_list = TlvIpAddrSet::default();
        info.ext_addr_list = TlvIpAddrSet::default();
        if let Some(a) = &local {
            info.local_addr_v4 = a.to_owned();
            info.local_addr_list.0.insert(entry(a));
        } else {
            info.local_addr_v4 = TlvIpAddress(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        }
        if let Some(a) = &ext {
            info.ext_addr_v4 = a.to_owned();
            info.ext_addr_list.0.insert(entry(a));
        } else {
            info.ext_addr_v4 = TlvIpAddress(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        }
        info
    }

    /// Sends our contact info and our own identities to a friend who just connected,
    /// like p3discovery2::sendOwnContactInfo().
    async fn send_own_info(&self, loc: Arc<SslId>) {
        let info = self.own_info().await;
        let payload = to_retroshare_wire(&info);
        #[allow(deprecated)]
        let header = ServiceHeader::new(self.get_id(), DISCOVERY_SUB_TYPE_CONTACT, &payload).into();
        info!("sending contact info to {loc}");
        debug!("contact info ({} bytes): {}", payload.len(), hex::encode(&payload));
        send_to_core!(self, Packet::new(header, payload, loc.clone()));

        // our own identities, so the friend can fetch them (needed for chat lobbies)
        let own_ids: Vec<GxsId> = self
            .core
            .get_service_data()
            .gxs_id()
            .get_group_meta_all()
            .await
            .into_iter()
            .filter(|g| g.subscribe_flags.contains(SubscribeFlags::ADMIN))
            .map(|g| GxsId::from(g.group_id.to_vec()))
            .collect();
        if !own_ids.is_empty() {
            let item = DiscIdentityListItem {
                own_identity_list: own_ids,
            };
            let payload = to_retroshare_wire(&item);
            let header =
                ServiceHeader::new(self.get_id(), DISCOVERY_SUB_TYPE_IDENTITY_LIST, &payload).into();
            send_to_core!(self, Packet::new(header, payload, loc));
        }
    }

    fn handle_incoming(&self, header: &ServiceHeader, mut packet: Packet) {
        match header.sub_type {
            #[allow(deprecated)]
            DISCOVERY_SUB_TYPE_CONTACT => {
                let item = read_rs_disc_contact_item(&mut packet.payload);
                // println!("received DiscContactItem: {}", item);
                // println!("pgp_id: {}", item.pgp_id);
                // println!("ssl_id: {}", item.ssl_id);

                if item.ssl_id == *self.own_id {
                    // describing us self: the friend tells us the address it sees us at,
                    // that's how RetroShare learns its public IP (recvOwnContactInfo)
                    info!("DiscContactItem: received our info");
                    let seen = item.current_connect_address.0.ip();
                    if crate::upnp::is_public_ip(&seen) {
                        let core = self.core.clone();
                        tokio::spawn(async move {
                            if let Some(mut own) = core.get_own_peers_cfg_item().await {
                                // the friend saw our outgoing port, we listen on our own port
                                let port = own.local_addr_v4.0.port();
                                let ext = SocketAddr::new(seen, port);
                                if port != 0 && own.ext_addr_v4.0 != ext {
                                    info!("learned our external address {ext} from a friend");
                                    own.ext_addr_v4 = TlvIpAddress(ext);
                                    if let Err(err) = core.update_peers_cfg(own).await {
                                        warn!("can't save external address: {err}");
                                    }
                                }
                            }
                        });
                    }
                } else {
                    self.handle_peer_contact(&item, packet.peer_id.clone());
                }
            }
            DISCOVERY_SUB_TYPE_IDENTITY_LIST => {
                let item: DiscIdentityListItem = from_retroshare_wire(&mut packet.payload);
                info!("received DiscIdentityListItem: {item}");
            }
            DISCOVERY_SUB_TYPE_PGP_LIST
            | DISCOVERY_SUB_TYPE_PGP_CERT
            | DISCOVERY_SUB_TYPE_PGP_CERT_BINARY => {
                info!("received {header:?}");
            }
            sub_type => {
                warn!("received unknown sub typ {sub_type}");
            }
        }
    }

    fn handle_peer_contact(&self, contact: &DiscContactItem, from: Arc<SslId>) {
        if contact.ssl_id == *from {
            // describing themselves; remember its version like p3discovery2::setPeerVersion()
            self.core
                .set_peer_version(&from.to_string(), contact.version.to_string());
            if contact.vs_disc != VsDisc::Off as u16 {
                // send own DISCOVERY_SUB_TYPE_PGP_LIST
                let mut item = DiscPgpListItem {
                    mode: GossipDiscoveryPgpListMode::Friends,
                    pgp_id_set: TlvPgpIdSet::default(),
                };

                for p in &self.core.get_persons() {
                    item.pgp_id_set.0.insert(p.get_pgp_id().to_owned());
                }

                let payload = to_retroshare_wire(&item);
                let header =
                    ServiceHeader::new(self.get_id(), DISCOVERY_SUB_TYPE_PGP_LIST, &payload).into();

                send_to_core!(self, Packet::new(header, payload, from));
            }
        } else {
            // describing someone else
            debug!(
                "DiscContactItem: received common friend peer info {}",
                contact.ssl_id
            );

            // unknown location of a friend (same PGP key): add it, like RetroShare
            if self.core.get_location_by_id(Arc::new(contact.ssl_id)).is_none()
                && self.core.get_person_by_pgp_id(&contact.pgp_id).is_some()
            {
                let core = self.core.clone();
                let (ssl_id, pgp_id) = (contact.ssl_id, contact.pgp_id);
                let name = contact.location.to_string();
                let local = contact.local_addr_list.to_owned();
                let external = contact.ext_addr_list.to_owned();
                let local_v4 = contact.local_addr_v4.to_owned();
                let ext_v4 = contact.ext_addr_v4.to_owned();
                let last_contact = contact.last_contact;
                tokio::spawn(async move {
                    crate::invite::add_location_of_friend(
                        &core, ssl_id, pgp_id, name, local, external, local_v4, ext_v4,
                        last_contact,
                    )
                    .await;
                });
                return;
            }

            // not our friend: remember as friend of a friend, nothing else to do
            if self.core.get_location_by_id(Arc::new(contact.ssl_id)).is_none() {
                let addresses = contact
                    .local_addr_list
                    .0
                    .iter()
                    .chain(contact.ext_addr_list.0.iter())
                    .map(|a| a.addr.0.to_string())
                    .collect();
                self.core.add_friend_of_friend(
                    contact.ssl_id,
                    crate::model::FriendOfFriend {
                        ssl_id: contact.ssl_id.to_string(),
                        pgp_id: contact.pgp_id.to_string(),
                        location: contact.location.to_string(),
                        addresses,
                        via: vec![from.to_string()],
                    },
                );
                return;
            }

            let local = contact.local_addr_list.0.to_owned();
            let external = contact.ext_addr_list.0.to_owned();
            self.core_tx
                .send(Intercom::PeerUpdate(PeerUpdate::Address(
                    Arc::new(contact.ssl_id),
                    local,
                    external,
                )))
                .expect("failed to communicate with core");
        }
    }
}

#[async_trait]
impl Service for Discovery {
    fn get_id(&self) -> ServiceType {
        ServiceType::Discovery
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "disc")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                select! {
                    msg = self.rx.recv() => {
                        if let Some(msg) = msg {
                            trace!("handling msg {msg:?}");

                            match msg {
                                Intercom::Receive(packet) => self.handle_incoming(&packet.header.to_owned().into(), packet),
                                _ => warn!("unexpected message: {msg:?}"),
                            }
                        } else {
                            break; // channel closed: stop instead of spinning
                        }
                    }
                    loc = self.delayed_rx.recv() => {
                        if let Some(loc) = loc {
                            if self.core.is_online(loc.clone()).await {
                                self.send_own_info(loc).await;
                            }
                        }
                    }
                    event = self.events_rx.recv() => {
                        if let Some(event) = event {
                            match event {
                                // like p3discovery2 (on RS_SERVICE_PEER_CONNECTED): only once the friend
                                // talks to us and knows our services, else RetroShare drops the item
                                Intercom::PeerUpdate(PeerUpdate::Seen(loc)) => {
                                    let tx = self.delayed_tx.clone();
                                    tokio::spawn(async move {
                                        tokio::time::sleep(CONTACT_INFO_DELAY).await;
                                        let _ = tx.send(loc);
                                    });
                                }
                                // we don't care for the rest!
                                _ => {}
                            }
                        }
                    }
                }
            }
        })
    }
}
