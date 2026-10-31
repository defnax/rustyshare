//! Incoming connections: TLS listener on the location's port.
//!
//! Like libretroshare's `pqissllistener`, the peer must present a certificate, which
//! is checked with the same rules as outgoing connections (see `verify.rs`), and the
//! location must be one of our friends.

use std::{net::SocketAddr, sync::Arc, time::SystemTime};

use log::{info, warn};
use rustls::{
    server::{ClientCertVerified, ClientCertVerifier},
    Certificate, DistinguishedNames, ServerConfig,
};
use tokio::{net::TcpListener, sync::mpsc::UnboundedSender};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use super::verify;
use crate::{
    model::{location::Location, DataCore},
    retroshare_compat::ssl_key::SslKey,
};

/// A verified incoming connection, handed to the core controller.
pub type IncomingConnection = (Arc<Location>, TlsStream<tokio::net::TcpStream>, SocketAddr);

/// Accepts only friends, checked against the live friend list.
struct FriendVerifier {
    data_core: Arc<DataCore>,
}

impl ClientCertVerifier for FriendVerifier {
    fn client_auth_root_subjects(&self) -> Option<DistinguishedNames> {
        Some(DistinguishedNames::new())
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _now: SystemTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let check = || -> verify::VerifyResult<()> {
            let id = verify::cert_ssl_id(&end_entity.0)?;
            if id == *self.data_core.get_own_location().get_location_id() {
                return Err("peer uses our own location id".into());
            }
            let location = self
                .data_core
                .get_location_by_id(Arc::new(id))
                .ok_or_else(|| format!("location {id} is not a friend"))?;
            let person = location.get_person();
            verify::check_peer_cert(&end_entity.0, person.get_pgp(), Some(&id))?;
            Ok(())
        };
        match check() {
            Ok(()) => Ok(ClientCertVerified::assertion()),
            Err(err) => {
                warn!("rejecting incoming connection: {err}");
                Err(rustls::Error::General(err))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &rustls::internal::msgs::handshake::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        verify::verify_handshake_sig(&cert.0, message, dss.scheme, &dss.sig.0)
            .map(|_| rustls::client::HandshakeSignatureValid::assertion())
            .map_err(rustls::Error::General)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &rustls::internal::msgs::handshake::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        verify::verify_handshake_sig(&cert.0, message, dss.scheme, &dss.sig.0)
            .map(|_| rustls::client::HandshakeSignatureValid::assertion())
            .map_err(rustls::Error::General)
    }
}

/// Listens on `port` (all interfaces) and passes verified friends to `incoming_tx`.
pub async fn run_listener(
    port: u16,
    own_key: SslKey,
    data_core: Arc<DataCore>,
    incoming_tx: UnboundedSender<IncomingConnection>,
) {
    let verifier = Arc::new(FriendVerifier {
        data_core: data_core.clone(),
    });
    let config = match ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![(&own_key).into()], (&own_key).into())
    {
        Ok(c) => c,
        Err(err) => {
            log::error!("listener: invalid own certificate/key: {err}");
            return;
        }
    };
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(err) => {
            log::error!("listener: can't listen on port {port}: {err}");
            return;
        }
    };
    info!("listening for friends on port {port}");

    loop {
        let (socket, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(err) => {
                warn!("listener: accept failed: {err}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let data_core = data_core.clone();
        let incoming_tx = incoming_tx.clone();

        tokio::spawn(async move {
            let stream = match acceptor.accept(socket).await {
                Ok(s) => s,
                Err(err) => {
                    info!("incoming connection from {addr} failed: {err}");
                    return;
                }
            };
            // the verifier already checked it, just find the location again
            let location = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|cert| verify::cert_ssl_id(&cert.0).ok())
                .and_then(|id| data_core.get_location_by_id(Arc::new(id)));
            match location {
                Some(location) => {
                    info!("incoming connection from {} ({addr})", location.get_name());
                    let _ = incoming_tx.send((location, stream, addr));
                }
                None => warn!("incoming connection from {addr} without a known location"),
            }
        });
    }
}
