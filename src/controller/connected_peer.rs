use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use log::{debug, info, trace, warn};
use retroshare_compat::services::service_info::RsServiceInfo;
use tokio::{
    io::{self, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use crate::{
    error::RsError,
    low_level_parsing::{
        headers::{Header, HEADER_SIZE},
        parser_network::Parser,
        Packet,
    },
    model::{
        intercom::{Intercom, PeerState, PeerThreadCommand, PeerUpdate},
        location::Location,
    },
    retroshare_compat::ssl_key::SslKey,
    services::{service_info, Services},
    transport_ng::ConnectionType,
};

use super::CoreController;

/// time for TCP + TLS to one address of a friend
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub struct ConnectedPeer {}

/// Bulk data waits for the upload limit, everything else (heartbeat, status, chat,
/// discovery, ...) is sent right away, like RetroShare's QoS queue in pqistreamer:
/// GXS (forums, identities, ...), turtle, file transfer, global router, GXS tunnels.
fn is_bulk(packet: &Packet) -> bool {
    match &packet.header {
        Header::Service { service, .. } => {
            let s = u16::from(*service);
            (0x0200..=0x02ff).contains(&s) || matches!(s, 0x0014 | 0x0017 | 0x0018 | 0x0019 | 0x0028)
        }
        _ => false,
    }
}

impl ConnectedPeer {
    pub async fn run<T: AsyncRead + AsyncWrite + Send + 'static>(
        mut rx: UnboundedReceiver<Intercom>,
        peer_tx: UnboundedSender<Intercom>, // requires own tx for services
        core_tx: UnboundedSender<Intercom>,
        tls_stream: T,
        location: Arc<Location>,
        mut global_services: Vec<RsServiceInfo>,
    ) {
        let (mut stream_read, mut stream_write) = split(tls_stream);

        let mut services = Services::get_peer_services(core_tx.to_owned(), peer_tx).await;
        let mut parser = Parser::new(location.get_location_id());

        let mut service_infos = services.get_service_infos();
        service_infos.append(&mut global_services);
        crate::service_control::register(&service_infos);
        let peer_key: crate::service_control::Id = location.get_location_id().0;
        let mut permissions_changed = crate::service_control::subscribe();

        // boot up
        // send through parser; only the services this friend may use (service permissions)
        let packet = service_info::ServiceInfo::gen_service_info(
            &crate::service_control::filter_for(&peer_key, &service_infos),
        );
        if let Err(err) = ConnectedPeer::send_packet(&mut stream_write, &mut parser, packet).await {
            warn!("[peer] can't start connection to {}: {err:?}", location.get_name());
            return;
        }

        core_tx
            .send(Intercom::PeerUpdate(PeerUpdate::Status(
                PeerState::Connected(
                    location.get_location_id(),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                ),
            )))
            .expect("failed to send");

        if log::log_enabled!(log::Level::Info) {
            info!("Peer ({}) starting ...", location.get_name());
            info!("registered core services:");
            for s in services.get_services() {
                info!(" - {:04X?}: {:?}", s as u16, s);
            }
        }

        // Reading runs in its own task: a read must never be cancelled in the middle of
        // a packet (that would lose bytes and mix up the stream). The download limit
        // makes it wait there, so TCP slows the friend down.
        let (net_tx, mut net_rx) = unbounded_channel();
        let reader = tokio::spawn(async move {
            loop {
                let res = ConnectedPeer::receive_packet(&mut stream_read).await;
                let failed = res.is_err();
                if let Ok((_, payload)) = &res {
                    crate::bandwidth::down().consume(HEADER_SIZE + payload.len()).await;
                }
                if net_tx.send(res).is_err() || failed {
                    break;
                }
            }
        });

        // bulk data waiting for the upload limit (already sliced)
        let mut bulk: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
        let mut bulk_wait: Option<tokio::time::Instant> = None;

        // enter main loop
        let mut seen = false;
        loop {
            tokio::select! {
                res = net_rx.recv() => {
                    trace!("net");

                    match res {
                        Some(Ok((header, payload))) => {
                            if !seen {
                                seen = true;
                                let _ = core_tx.send(Intercom::PeerUpdate(PeerUpdate::Seen(
                                    location.get_location_id(),
                                )));
                            }
                            if let Some(packet) = parser.handle_incoming_packet(header, payload) {
                                trace!("handling packet {packet:?}");
                                if let Header::Service { service, .. } = &packet.header {
                                    if !crate::service_control::allowed(&peer_key, u16::from(*service)) {
                                        debug!("[peer] dropping {service:?} packet from {}: service not allowed", location.get_name());
                                        continue;
                                    }
                                }

                                // if there is no fitting peer service, the packet will be forwarded to the core
                                crate::watchdog::PACKETS_IN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                services.handle_packet(packet).await;
                            }
                        }
                        Some(Err(err)) => {
                            let text = format!("{err:?}");
                            if text.contains("AlertReceived(UnknownCA)")
                                || text.contains("AlertReceived(BadCertificate)")
                                || text.contains("AlertReceived(CertificateUnknown)")
                                || text.contains("AlertReceived(AccessDenied)")
                            {
                                warn!(
                                    "[peer] {} ({}) refused our certificate: that location doesn't have us as a friend",
                                    location.get_name(),
                                    location.get_location_id()
                                );
                            } else {
                                warn!("[peer] connection to {} closed: {err:?}", location.get_name());
                            }
                            break;
                        }
                        None => {
                            warn!("[peer] connection to {} closed (reader stopped)", location.get_name());
                            break;
                        }
                    }
                }
                res = rx.recv() => {
                    trace!("queue");

                    match res {
                        Some(Intercom::Send(packet)) => {
                            if let Header::Service { service, .. } = &packet.header {
                                if !crate::service_control::allowed(&peer_key, u16::from(*service)) {
                                    trace!("[peer] not sending {service:?} to {}: service not allowed", location.get_name());
                                    continue;
                                }
                            }
                            crate::watchdog::PACKETS_OUT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let bulk_packet = is_bulk(&packet);
                            let slices = parser.handle_outgoign_packet(packet);
                            if bulk_packet {
                                bulk.extend(slices);
                            } else {
                                let mut ok = true;
                                for slice in slices {
                                    crate::bandwidth::up().take_now(slice.len());
                                    if let Err(err) = stream_write.write_all(&slice).await {
                                        warn!("[peer] can't send to {}: {err:?}", location.get_name());
                                        ok = false;
                                        break;
                                    }
                                }
                                if !ok || stream_write.flush().await.is_err() {
                                    break;
                                }
                            }
                        }
                        // friend removed: end the connection
                        Some(Intercom::Thread(PeerThreadCommand::Stop)) => {
                            info!("[peer] closing connection to {}", location.get_name());
                            break;
                        }
                        Some(msg) => panic!("not implemented, received {msg:?}"),
                        // all senders gone (location removed), nothing will come anymore
                        None => break,
                    }
                }
                // service permissions changed: announce the new list (p3ServiceInfo)
                Ok(()) = permissions_changed.changed() => {
                    let packet = service_info::ServiceInfo::gen_service_info(
                        &crate::service_control::filter_for(&peer_key, &service_infos),
                    );
                    if let Err(err) = ConnectedPeer::send_packet(&mut stream_write, &mut parser, packet).await {
                        warn!("[peer] can't send to {}: {err:?}", location.get_name());
                        break;
                    }
                }
                _ = tokio::time::sleep_until(bulk_wait.unwrap_or_else(tokio::time::Instant::now)), if bulk_wait.is_some() => {
                    bulk_wait = None;
                }
            }

            // send queued bulk data as far as the upload limit allows
            if bulk_wait.is_none() && !bulk.is_empty() {
                let mut wrote = false;
                let mut failed = false;
                while let Some(slice) = bulk.front() {
                    match crate::bandwidth::up().try_take(slice.len()) {
                        None => {
                            if let Err(err) = stream_write.write_all(slice).await {
                                warn!("[peer] can't send to {}: {err:?}", location.get_name());
                                failed = true;
                                break;
                            }
                            bulk.pop_front();
                            wrote = true;
                        }
                        Some(wait) => {
                            bulk_wait = Some(tokio::time::Instant::now() + wait);
                            break;
                        }
                    }
                }
                if failed || (wrote && stream_write.flush().await.is_err()) {
                    break;
                }
            }
        }
        reader.abort();
    }

    async fn receive_packet<T: AsyncRead + std::marker::Unpin>(
        stream: &mut T,
    ) -> Result<(Header, Vec<u8>), RsError> {
        // read header
        let mut header = [0; HEADER_SIZE]; // type + size
        match stream.read_exact(&mut header).await? {
            0 => {
                warn!("[peer] zero read");
                Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset).into())
            }
            HEADER_SIZE => {
                // parse header
                let header = Header::try_parse(&header)?;
                debug!(">>> got header {header:?}");

                let payload_size = header.get_payload_size();
                debug!(">>> reading {} bytes payload", payload_size);
                let mut payload = vec![];
                payload.resize(payload_size, 0);

                let len = stream.read_exact(payload.as_mut_slice()).await?;
                assert_eq!(payload_size, len);

                trace!(">>> read: {payload:02X?}");
                Ok((header, payload))
            }
            length => {
                log::error!("unable to read full header, only got {length} bytes: {header:02X?}");
                // fail graceful one day?
                panic!("can't hanlde too short");
            }
        }
    }

    async fn send_packet<T: AsyncWrite + std::marker::Unpin>(
        stream: &mut T,
        parser: &mut Parser,
        packet: Packet,
    ) -> io::Result<()> {
        debug!("<<< send_packet to {}", packet.peer_id);
        debug!("<<< header {:?}", packet.header);
        trace!("<<< payload {:02X?}", packet.payload);

        for packet in parser.handle_outgoign_packet(packet) {
            crate::bandwidth::up().take_now(packet.len());
            stream.write_all(&packet).await?;
        }
        stream.flush().await
    }
}

pub(super) struct ConnectionBuilder {
    peer_location: Arc<Location>,
    // own_peer_id: Arc<PeerId>,
    own_key_pair: SslKey,

    core_tx: UnboundedSender<Intercom>,

    peer_rx: UnboundedReceiver<Intercom>,
    peer_tx: UnboundedSender<Intercom>,

    global_services: Vec<RsServiceInfo>,
}

impl ConnectionBuilder {
    pub fn new(
        cc: &CoreController,
        peer_location: Arc<Location>,
    ) -> (Self, UnboundedSender<Intercom>) {
        let own_peer_id = cc.data_core.get_own_location().get_location_id();
        let own_key_pair = cc.data_core.get_own_keypair().to_owned();
        let core_tx = cc.core_tx.clone();
        let (peer_tx, peer_rx) = unbounded_channel();
        let global_services = cc.services.get_service_infos();

        assert_ne!(peer_location.get_location_id(), own_peer_id);

        (
            ConnectionBuilder {
                peer_location,
                // own_peer_id,
                own_key_pair,

                core_tx,

                peer_rx,
                peer_tx: peer_tx.to_owned(),

                global_services,
            },
            peer_tx,
        )
    }

    /// Runs the peer on an established (and verified) TLS stream, outgoing or incoming.
    pub(super) fn start<T>(self, tls_stream: T) -> JoinHandle<()>
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        tokio::spawn(async move {
            // in its own task: even if it panics, the core must hear that the friend is
            // gone (else the connection would count as "running" forever)
            let res = tokio::spawn(ConnectedPeer::run(
                self.peer_rx,
                self.peer_tx,
                self.core_tx.to_owned(),
                tls_stream,
                self.peer_location.clone(),
                self.global_services,
            ))
            .await;
            if let Err(err) = res {
                warn!("[peer] connection task of {} crashed: {err}", self.peer_location.get_name());
            }

            // disconnected
            self.core_tx
                .send(Intercom::PeerUpdate(PeerUpdate::Status(
                    PeerState::NotConnected(self.peer_location.get_location_id()),
                )))
                .expect("failed to send");
        })
    }

    pub(super) async fn connect(self) -> Option<JoinHandle<()>> {
        trace!("trying to connect to {}", self.peer_location.get_name());
        // turn IPs into ConnectionType::Tcp
        let ips = {
            let ips = self.peer_location.get_ips();
            let mut local: Vec<ConnectionType> = ips
                .0
                .iter()
                .map(|val| ConnectionType::Tcp(val.addr.0))
                .collect();
            let mut external: Vec<ConnectionType> = ips
                .1
                .iter()
                .map(|val| ConnectionType::Tcp(val.addr.0))
                .collect();
            local.append(&mut external);
            local
        };

        let _loc_id = self.peer_location.get_location_id().to_owned();
        let loc_key = self.peer_location.get_person().get_pgp().to_owned();

        // try to connect
        if let Ok(con) = crate::transport_ng::Connection::new(
            &self.own_key_pair,
            loc_key,
            *self.peer_location.get_location_id(),
        ) {
            for ip in ips {
                trace!(
                    "trying to connect to {} with ip {:?}",
                    self.peer_location.get_name(),
                    ip
                );

                // don't hang for long on addresses that don't answer (link local, old IPs)
                match tokio::time::timeout(CONNECT_TIMEOUT, con.connect(ip)).await {
                    Ok(Ok(tls_stream)) => {
                        trace!("connected to {}!", self.peer_location.get_name());
                        return Some(self.start(tls_stream));
                    }
                    _ => continue,
                }
            }
        } else {
            warn!("failed to connect to {}", self.peer_location.get_name());
        }

        // failed to connect: tell the core, so the attempt is not "running" forever
        self.core_tx
            .send(Intercom::PeerUpdate(PeerUpdate::Status(
                PeerState::NotConnected(self.peer_location.get_location_id()),
            )))
            .expect("failed to send");
        None
    }
}
