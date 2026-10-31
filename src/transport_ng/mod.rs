use futures::io;
use log::{info, warn};
use retroshare_compat::basics::SslId;
#[allow(unused_imports)]
use openpgp::parse::Parse;
#[allow(unused_imports)]
use openssl::{self, hash::MessageDigest};
use rustls::{
    client::{InvalidDnsNameError, ServerCertVerifier},
    Certificate, ClientConfig, ServerName,
};
use sequoia_openpgp as openpgp;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

use crate::retroshare_compat::ssl_key::SslKey;

pub mod listener;
pub mod verify;

#[derive(Clone, Debug)]
pub enum ConnectionType {
    Tcp(SocketAddr),
    #[allow(dead_code)]
    Udp(SocketAddr),
}

/// Verifies the server (the friend we dial) like libretroshare's `VerifyX509Callback()`.
struct PeerVerifier {
    peer_cert: sequoia_openpgp::Cert,
    expected_id: SslId,
}

impl ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        match verify::check_peer_cert(&end_entity.0, &self.peer_cert, Some(&self.expected_id)) {
            Ok(id) => {
                info!("verified certificate of {id}");
                Ok(rustls::client::ServerCertVerified::assertion())
            }
            Err(err) => {
                warn!("rejecting peer {}: {err}", self.expected_id);
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

pub struct Connection {
    config: Arc<ClientConfig>,
    peer_name: ServerName,
}

impl Connection {
    pub fn new(
        own_key_pair: &SslKey,
        peer_cert: sequoia_openpgp::Cert,
        expected_id: SslId,
    ) -> Result<Self, InvalidDnsNameError> {
        // RetroShare doesn't use the server name, but rustls needs a valid DNS name
        // (location names like "My computer" are not), so use the location id.
        let peer_name: ServerName = format!("{expected_id}.rs").as_str().try_into()?;

        let verifier = Arc::new(PeerVerifier {
            peer_cert,
            expected_id,
        });

        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(verifier)
            .with_single_cert(vec![own_key_pair.into()], own_key_pair.into())
            .expect("faield to load key pair");

        let config = Arc::new(config);

        Ok(Connection { config, peer_name })
    }

    pub async fn connect(&self, target: ConnectionType) -> io::Result<impl AsyncWrite + AsyncRead> {
        let ip_addr = match target {
            ConnectionType::Tcp(ip) => ip,
            ConnectionType::Udp(_) => unimplemented!("UDP support not implemented"),
        };

        let connector = TlsConnector::from(self.config.clone());
        let stream = TcpStream::connect(&ip_addr).await?;
        connector.connect(self.peer_name.clone(), stream).await
    }
}
