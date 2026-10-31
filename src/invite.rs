//! RetroShare invites ("certificates"), following libretroshare's `pgp/rscertificate.cc`.
//!
//! Format: radix64 (base64) of a list of packets `[ptag: u8][size: OpenPGP length][data]`,
//! ending with a 24 bit CRC packet. Version 0x06.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use openpgp::{parse::Parse, serialize::SerializeInto, Cert};
use retroshare_compat::{
    basics::{PgpId, SslId},
    config::PeerNetItem,
    tlv::{
        tlv_ip_addr::{TlvIpAddress, TlvIpAddressInfo, TlvIpAddressInfoInner},
        tlv_set::TlvSet,
        Tlv,
    },
};
use sequoia_openpgp as openpgp;

use crate::model::{location::Location, person::Peer, DataCore};

const CERTIFICATE_VERSION_06: u8 = 0x06;

const PTAG_PGP: u8 = 0x01;
const PTAG_EXT_IP: u8 = 0x02;
const PTAG_LOC_IP: u8 = 0x03;
const PTAG_DNS: u8 = 0x04;
const PTAG_SSLID: u8 = 0x05;
const PTAG_NAME: u8 = 0x06;
const PTAG_CHECKSUM: u8 = 0x07;
const PTAG_HIDDEN: u8 = 0x08;
const PTAG_VERSION: u8 = 0x09;
const PTAG_EXTRA_LOCATOR: u8 = 10;

/// A parsed RetroShare invite.
pub struct Invite {
    pub pgp: Cert,
    pub location_name: String,
    pub ssl_id: Option<SslId>,
    pub ext_addr: Option<SocketAddr>,
    pub local_addr: Option<SocketAddr>,
    pub dns: Option<String>,
    pub hidden_address: Option<String>,
    pub locators: Vec<String>,
}

/// OpenPGP CRC-24 (RFC 4880, 6.1), as used by `PGPKeyManagement::compute24bitsCRC()`.
fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xB7_04CE;
    for &b in data {
        crc ^= (b as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x100_0000 != 0 {
                crc ^= 0x186_4CFB;
            }
        }
    }
    crc & 0xFF_FFFF
}

/// OpenPGP new format length ("125 size").
fn read_length(data: &[u8], pos: &mut usize) -> Result<usize, String> {
    let b0 = *data.get(*pos).ok_or("invite truncated")? as usize;
    *pos += 1;
    if b0 < 192 {
        Ok(b0)
    } else if b0 < 224 {
        let b1 = *data.get(*pos).ok_or("invite truncated")? as usize;
        *pos += 1;
        Ok(((b0 - 192) << 8) + b1 + 192)
    } else if b0 == 255 {
        let b = data.get(*pos..*pos + 4).ok_or("invite truncated")?;
        *pos += 4;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    } else {
        Err("invalid length in invite".into())
    }
}

fn write_length(out: &mut Vec<u8>, len: usize) {
    if len < 192 {
        out.push(len as u8);
    } else if len < 8384 {
        let l = len - 192;
        out.push(((l >> 8) + 192) as u8);
        out.push((l & 0xff) as u8);
    } else {
        out.push(255);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn add_packet(out: &mut Vec<u8>, ptag: u8, data: &[u8]) {
    out.push(ptag);
    write_length(out, data.len());
    out.extend_from_slice(data);
}

fn parse_ip(data: &[u8]) -> Option<SocketAddr> {
    if data.len() != 6 {
        return None;
    }
    let ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
    let port = u16::from_be_bytes([data[4], data[5]]);
    if ip.is_unspecified() || port == 0 {
        return None;
    }
    Some(SocketAddr::new(IpAddr::V4(ip), port))
}

fn ip_bytes(addr: Option<SocketAddr>) -> [u8; 6] {
    match addr {
        Some(SocketAddr::V4(a)) => {
            let o = a.ip().octets();
            let p = a.port().to_be_bytes();
            [o[0], o[1], o[2], o[3], p[0], p[1]]
        }
        _ => [0; 6],
    }
}

/// Parses a RetroShare invite (the long certificate text).
pub fn parse_invite(text: &str) -> Result<Invite, String> {
    let text = text.trim();
    if text.contains("rsInvite=") || text.starts_with("http") {
        return Err(
            "short invites (links) are not supported yet, please use the full certificate".into(),
        );
    }

    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let data = base64::decode(&cleaned).map_err(|e| format!("invite is not valid base64: {e}"))?;

    let mut pgp = None;
    let mut invite_version = 0;
    let mut checksum_ok = false;
    let mut location_name = String::new();
    let mut ssl_id = None;
    let mut ext_addr = None;
    let mut local_addr = None;
    let mut dns = None;
    let mut hidden_address = None;
    let mut locators = vec![];

    let mut pos = 0;
    while pos < data.len() {
        let packet_start = pos;
        let ptag = data[pos];
        pos += 1;
        let len = read_length(&data, &mut pos)?;
        let body = data.get(pos..pos + len).ok_or("invite truncated")?;
        pos += len;

        match ptag {
            PTAG_VERSION => invite_version = *body.first().unwrap_or(&0),
            PTAG_PGP => pgp = Some(body.to_vec()),
            PTAG_NAME => location_name = String::from_utf8_lossy(body).to_string(),
            PTAG_SSLID => {
                let id: [u8; 16] = body
                    .try_into()
                    .map_err(|_| "invalid location id in invite")?;
                ssl_id = Some(SslId(id));
            }
            PTAG_DNS => dns = Some(String::from_utf8_lossy(body).to_string()),
            PTAG_HIDDEN => hidden_address = Some(String::from_utf8_lossy(body).to_string()),
            PTAG_LOC_IP => local_addr = parse_ip(body),
            PTAG_EXT_IP => ext_addr = parse_ip(body),
            PTAG_EXTRA_LOCATOR => locators.push(String::from_utf8_lossy(body).to_string()),
            PTAG_CHECKSUM => {
                if body.len() != 3 || pos != data.len() {
                    return Err("invalid checksum section in invite".into());
                }
                let expected = body[0] as u32 | (body[1] as u32) << 8 | (body[2] as u32) << 16;
                if crc24(&data[..packet_start]) == expected {
                    checksum_ok = true;
                } else {
                    return Err("invite checksum is wrong (copied incompletely?)".into());
                }
            }
            other => log::warn!("unknown packet {other} in invite, ignoring it"),
        }
    }

    if !checksum_ok {
        return Err("invite has no checksum (copied incompletely?)".into());
    }
    if invite_version != CERTIFICATE_VERSION_06 {
        return Err(format!("unsupported invite version {invite_version}"));
    }
    let pgp = pgp.ok_or("invite contains no PGP key")?;
    let pgp = Cert::from_bytes(&pgp).map_err(|e| format!("invalid PGP key in invite: {e}"))?;

    Ok(Invite {
        pgp,
        location_name,
        ssl_id,
        ext_addr,
        local_addr,
        dns,
        hidden_address,
        locators,
    })
}

/// Builds our own invite, like `RsCertificate::toStdString()`.
pub fn make_invite(
    pgp_public: &Cert,
    location_name: &str,
    ssl_id: &SslId,
    local_addr: Option<SocketAddr>,
    ext_addr: Option<SocketAddr>,
) -> Result<String, String> {
    let pgp_bytes = pgp_public
        .clone()
        .strip_secret_key_material()
        .to_vec()
        .map_err(|e| e.to_string())?;

    let mut buf = vec![];
    add_packet(&mut buf, PTAG_VERSION, &[CERTIFICATE_VERSION_06]);
    add_packet(&mut buf, PTAG_PGP, &pgp_bytes);
    add_packet(&mut buf, PTAG_EXT_IP, &ip_bytes(ext_addr));
    add_packet(&mut buf, PTAG_LOC_IP, &ip_bytes(local_addr));
    add_packet(&mut buf, PTAG_NAME, location_name.as_bytes());
    add_packet(&mut buf, PTAG_SSLID, &ssl_id.0);

    let crc = crc24(&buf);
    add_packet(
        &mut buf,
        PTAG_CHECKSUM,
        &[(crc & 0xff) as u8, (crc >> 8 & 0xff) as u8, (crc >> 16 & 0xff) as u8],
    );
    Ok(base64::encode(&buf))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn addr_info(addr: SocketAddr) -> TlvIpAddressInfo {
    Tlv(TlvIpAddressInfoInner {
        addr: TlvIpAddress(addr),
        seen_time: now(),
        source: 0,
    })
}

/// Builds a `peers.cfg` entry for a location.
pub fn make_peer_net_item(
    ssl_id: SslId,
    pgp_id: PgpId,
    location_name: &str,
    local_addr: Option<SocketAddr>,
    ext_addr: Option<SocketAddr>,
    dns: Option<&str>,
) -> PeerNetItem {
    let set = |a: Option<SocketAddr>| {
        let mut s = HashSet::new();
        if let Some(a) = a {
            s.insert(addr_info(a));
        }
        TlvSet(s)
    };
    PeerNetItem {
        node_peer_id: ssl_id,
        pgp_id,
        location: location_name.into(),
        net_mode: 0,
        vs_disc: 2, // RS_VS_DISC_FULL
        vs_dht: 2,  // RS_VS_DHT_FULL
        last_contact: 0,
        local_addr_v4: local_addr.map(TlvIpAddress).unwrap_or_default(),
        ext_addr_v4: ext_addr.map(TlvIpAddress).unwrap_or_default(),
        local_addr_v6: TlvIpAddress::default(),
        ext_addr_v6: TlvIpAddress::default(),
        dyndns: dns.unwrap_or("").into(),
        local_addr_list: set(local_addr),
        ext_addr_list: set(ext_addr),
        domain_addr: "".into(),
        domain_port: 0,
    }
}

fn pgp_id_of(cert: &Cert) -> PgpId {
    PgpId(
        cert.keyid()
            .as_bytes()
            .try_into()
            .expect("PGP key id is 8 bytes"),
    )
}

/// Appends a friend's public key to the public keyring (creates it if needed).
fn import_public_key(data_core: &DataCore, cert: &Cert) -> Result<(), String> {
    let dir = crate::profile::keyring_dir(data_core.get_base_dir());
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let bytes = cert
        .clone()
        .strip_secret_key_material()
        .to_vec()
        .map_err(|e| e.to_string())?;
    crate::profile::append_with_backup(&dir.join("retroshare_public_keyring.gpg"), &bytes)
        .map_err(|e| e.to_string())
}

/// Adds another location of a friend whose PGP key we already accepted, learned through
/// discovery. RetroShare does the same (p3discovery2): being friends with a PGP key
/// means all its locations are friends. Returns false if nothing was added.
pub async fn add_location_of_friend(
    data_core: &DataCore,
    ssl_id: SslId,
    pgp_id: PgpId,
    location_name: String,
    local: retroshare_compat::tlv::tlv_ip_addr::TlvIpAddrSet,
    external: retroshare_compat::tlv::tlv_ip_addr::TlvIpAddrSet,
    local_v4: TlvIpAddress,
    ext_v4: TlvIpAddress,
    last_contact: u32,
) -> bool {
    if data_core.get_location_by_id(Arc::new(ssl_id)).is_some()
        || ssl_id == *data_core.get_own_location().get_location_id()
    {
        return false;
    }
    let person = match data_core.get_person_by_pgp_id(&pgp_id) {
        Some(p) => p,
        None => return false, // not a friend's key
    };

    let location = Arc::new(Location::new(
        location_name.clone(),
        Arc::new(ssl_id),
        Arc::new(pgp_id),
        (
            local.0.iter().cloned().collect(),
            external.0.iter().cloned().collect(),
        ),
        person.clone(),
    ));
    let mut item = make_peer_net_item(ssl_id, pgp_id, &location_name, None, None, None);
    item.local_addr_v4 = local_v4;
    item.ext_addr_v4 = ext_v4;
    item.local_addr_list = local;
    item.ext_addr_list = external;
    // RetroShare fills lastContact with the time it sent the item, so it says nothing
    // about when the location was really online: start with "never"
    let _ = last_contact;

    match data_core.add_friend(person.clone(), location, item).await {
        Ok(()) => {
            log::info!(
                "added location {location_name} ({ssl_id}) of friend {}",
                person.get_name()
            );
            true
        }
        Err(err) => {
            log::warn!("can't save new location {location_name} of a friend: {err}");
            false
        }
    }
}

/// Adds the friend from an invite: imports the PGP key, adds the location and saves
/// `peers.cfg`. Returns a short description of the new friend.
pub async fn add_friend(data_core: &DataCore, invite: Invite) -> Result<String, String> {
    let ssl_id = invite
        .ssl_id
        .ok_or("this invite contains only a PGP key and no location")?;
    if invite.hidden_address.is_some() {
        log::warn!("invite is for a Tor/I2P node, rustyshare can't connect to those yet");
    }
    if ssl_id == *data_core.get_own_location().get_location_id() {
        return Err("this is your own invite".into());
    }
    if data_core.get_location_by_id(Arc::new(ssl_id)).is_some() {
        return Err("this location is already a friend".into());
    }

    let pgp_id = pgp_id_of(&invite.pgp);
    let name = invite
        .pgp
        .userids()
        .next()
        .map(|u| String::from_utf8_lossy(u.userid().value()).to_string())
        .unwrap_or_default();

    // person: reuse a known one (new location of an existing friend) or create
    let person = match data_core.get_person_by_pgp_id(&pgp_id) {
        Some(p) => p,
        None => {
            import_public_key(data_core, &invite.pgp)?;
            Arc::new(Peer::new(
                name.clone(),
                invite.pgp.clone().strip_secret_key_material(),
                pgp_id,
            ))
        }
    };

    let local: Vec<_> = invite.local_addr.into_iter().map(addr_info).collect();
    let ext: Vec<_> = invite.ext_addr.into_iter().map(addr_info).collect();
    let location = Arc::new(Location::new(
        invite.location_name.clone(),
        Arc::new(ssl_id),
        Arc::new(pgp_id),
        (local, ext),
        person.clone(),
    ));

    let item = make_peer_net_item(
        ssl_id,
        pgp_id,
        &invite.location_name,
        invite.local_addr,
        invite.ext_addr,
        invite.dns.as_deref(),
    );

    data_core
        .add_friend(person, location, item)
        .await
        .map_err(|e| format!("friend added, but saving peers.cfg failed: {e}"))?;

    Ok(format!(
        "{name} / {} ({ssl_id})",
        invite.location_name
    ))
}

/// Our own invite (long certificate), to give to friends.
pub async fn own_invite(data_core: &DataCore) -> Result<String, String> {
    let own = data_core.get_own_location();
    let item = data_core.get_own_peers_cfg_item().await;
    let local = item
        .as_ref()
        .map(|i| i.local_addr_v4.0)
        .filter(|a| a.port() != 0);
    let ext = item
        .as_ref()
        .map(|i| i.ext_addr_v4.0)
        .filter(|a| a.port() != 0 && crate::upnp::is_public_ip(&a.ip()));
    make_invite(
        own.get_person().get_pgp(),
        own.get_name(),
        &own.get_location_id(),
        local,
        ext,
    )
}
