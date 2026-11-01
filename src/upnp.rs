//! UPnP port forwarding (like libretroshare's `rs_upnp` / p3UpnpMgr): asks the router
//! to forward our listening port and tells us our external address.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use colored::Colorize;
use igd_next::{PortMappingProtocol, SearchOptions};
use log::{info, warn};

use crate::model::DataCore;

/// lease time of the mapping, renewed before it runs out
const LEASE_SECONDS: u32 = 60 * 60;

/// true for addresses reachable from the internet (not private, CGNAT, loopback, ...)
pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_unspecified()
                || v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || (o[0] == 100 && (o[1] & 0xC0) == 64)) // 100.64.0.0/10 carrier NAT
        }
        IpAddr::V6(_) => false, // only IPv4 is used for now
    }
}

/// Maps `port` on the router to `local` and returns our external address.
fn map_port(local: SocketAddr) -> Result<SocketAddr, String> {
    let gateway = igd_next::search_gateway(SearchOptions {
        timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    })
    .map_err(|e| format!("no UPnP router found ({e})"))?;

    let external_ip: IpAddr = gateway
        .get_external_ip()
        .map_err(|e| format!("router didn't tell the external IP ({e})"))?;

    gateway
        .add_port(
            PortMappingProtocol::TCP,
            local.port(),
            local,
            LEASE_SECONDS,
            "rustyshare",
        )
        .map_err(|e| format!("router refused the port forwarding ({e})"))?;

    Ok(SocketAddr::new(external_ip, local.port()))
}

/// OpenDNS resolvers that answer `myip.opendns.com` with the address the query came
/// from, like libretroshare's ExtAddrFinder.
const IP_FINDER_SERVERS: [&str; 4] = [
    "208.67.222.222",
    "208.67.220.220",
    "208.67.222.220",
    "208.67.220.222",
];

/// One DNS A query for `myip.opendns.com` at `server`.
async fn ask_dns(server: &str) -> Option<IpAddr> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect((server, 53)).await.ok()?;

    let id: u16 = {
        use nanorand::Rng;
        nanorand::WyRand::new().generate()
    };
    let mut query = vec![];
    query.extend(id.to_be_bytes());
    query.extend([0x01, 0x00]); // standard query, recursion desired
    query.extend([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // 1 question
    for label in ["myip", "opendns", "com"] {
        query.push(label.len() as u8);
        query.extend(label.as_bytes());
    }
    query.push(0);
    query.extend([0x00, 0x01, 0x00, 0x01]); // type A, class IN
    socket.send(&query).await.ok()?;

    let mut buf = [0u8; 512];
    let len = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    let resp = &buf[..len];
    if len < 12 || resp[0..2] != id.to_be_bytes() {
        return None;
    }
    let answers = u16::from_be_bytes([resp[6], resp[7]]);

    // skip the question
    let mut pos = 12;
    while pos < len && resp[pos] != 0 {
        pos += 1 + resp[pos] as usize;
    }
    pos += 5;

    for _ in 0..answers {
        // name: pointer or labels
        if *resp.get(pos)? & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            while pos < len && resp[pos] != 0 {
                pos += 1 + resp[pos] as usize;
            }
            pos += 1;
        }
        let head = resp.get(pos..pos + 10)?;
        let ty = u16::from_be_bytes([head[0], head[1]]);
        let rdlen = u16::from_be_bytes([head[8], head[9]]) as usize;
        pos += 10;
        let data = resp.get(pos..pos + rdlen)?;
        if ty == 1 && rdlen == 4 {
            return Some(IpAddr::from([data[0], data[1], data[2], data[3]]));
        }
        pos += rdlen;
    }
    None
}

/// Asks all servers and returns the address most of them reported.
pub async fn find_external_ip() -> Option<IpAddr> {
    let mut votes: std::collections::HashMap<IpAddr, u32> = std::collections::HashMap::new();
    for server in IP_FINDER_SERVERS {
        if let Some(ip) = ask_dns(server).await {
            if is_public_ip(&ip) {
                *votes.entry(ip).or_default() += 1;
            }
        }
    }
    votes.into_iter().max_by_key(|(_, n)| *n).map(|(ip, _)| ip)
}

async fn save_external(data_core: &DataCore, external: SocketAddr) {
    if let Some(mut item) = data_core.get_own_peers_cfg_item().await {
        if item.ext_addr_v4.0 != external {
            item.ext_addr_v4 = ::retroshare_compat::tlv::tlv_ip_addr::TlvIpAddress(external);
            if let Err(err) = data_core.update_peers_cfg(item).await {
                warn!("can't save external address: {err}");
            }
        }
    }
}

/// Keeps the port forwarding alive and stores the external address in peers.cfg
/// (which also puts it into our invite and discovery info). Without UPnP the
/// external IP is looked up via DNS (disable with --no-ip-finder).
pub async fn run(data_core: Arc<DataCore>, local: SocketAddr, use_upnp: bool, use_finder: bool) {
    if local.ip().is_unspecified() {
        warn!("local address unknown, skipping UPnP and external IP lookup");
        return;
    }
    let mut upnp_ok = use_upnp;
    let mut announced: Option<SocketAddr> = None;
    let mut first = true;

    loop {
        let mut external = None;
        let mut router_without_public_ip = false;

        if upnp_ok {
            match tokio::task::spawn_blocking(move || map_port(local)).await {
                Ok(Ok(ext)) if is_public_ip(&ext.ip()) => external = Some(ext),
                Ok(Ok(ext)) => {
                    router_without_public_ip = true;
                    if first {
                        println!(
                            "{} the router forwarded port {} but reports no public IP ({}). It is probably behind another router or your provider's NAT (DS-Lite/CGNAT).",
                            "UPnP:".yellow(),
                            local.port(),
                            ext.ip()
                        );
                    }
                }
                Ok(Err(err)) => {
                    if first {
                        println!("{} {err}.", "UPnP:".yellow());
                    }
                    // no UPnP router: don't keep asking
                    upnp_ok = false;
                }
                Err(err) => warn!("UPnP task failed: {err}"),
            }
        }

        if external.is_none() && use_finder {
            if let Some(ip) = find_external_ip().await {
                external = Some(SocketAddr::new(ip, local.port()));
                if first {
                    if router_without_public_ip {
                        println!(
                            "{} {} (via DNS). Your router has no public IP of its own, so friends outside your network can probably NOT connect to you; you can still connect to them.",
                            "External IP:".yellow(),
                            ip
                        );
                    } else if !upnp_ok {
                        println!(
                            "{} {} (via DNS). Forward port {} on your router to {} so friends outside your network can reach you.",
                            "External IP:".green(),
                            ip,
                            local.port(),
                            local
                        );
                    }
                }
            } else if first {
                println!("{} could not find out the external IP.", "External IP:".yellow());
            }
        }

        if let Some(ext) = external {
            if announced != Some(ext) {
                if upnp_ok && !router_without_public_ip {
                    println!("{} {} -> {}", "UPnP port forwarding active:".green(), ext, local);
                }
                info!("external address: {ext}");
                save_external(&data_core, ext).await;
                announced = Some(ext);
            }
        }

        first = false;
        // renew well before the UPnP lease runs out, and notice IP changes
        tokio::time::sleep(Duration::from_secs(LEASE_SECONDS as u64 / 2)).await;
    }
}
