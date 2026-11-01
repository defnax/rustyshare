use std::sync::Arc;

use actix_web::{
    post,
    web::{self},
    Responder, Result,
};
use retroshare_compat::basics::{SslIdHex, SslIdWrapped};
use serde::{Deserialize, Serialize};

use crate::{model::DataCore, webui::RetVal};

// rsPeers/GetRetroshareInvite
#[post("/GetRetroshareInvite")]
pub async fn rs_peers_get_rs_invite(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    let invite = crate::invite::own_invite(&state)
        .await
        .unwrap_or_else(|err| format!("error: {err}"));
    Ok(web::Json(RetVal { retval: invite }))
}

// rsPeers/acceptInvite
#[derive(Deserialize)]
pub struct AcceptInvite {
    invite: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptInviteResult {
    retval: bool,
    error_message: String,
}
#[post("/acceptInvite")]
pub async fn rs_peers_accept_invite(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<AcceptInvite>,
) -> Result<impl Responder> {
    let result = match crate::invite::parse_invite(&params.invite) {
        Ok(invite) => crate::invite::add_friend(&state, invite).await,
        Err(err) => Err(err),
    };
    Ok(web::Json(match result {
        Ok(who) => {
            log::info!("added friend {who}");
            AcceptInviteResult {
                retval: true,
                error_message: String::new(),
            }
        }
        Err(err) => AcceptInviteResult {
            retval: false,
            error_message: err,
        },
    }))
}

// rsPeers/GetShortInvite
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormatRadix {
    #[allow(dead_code)]
    format_radix: bool,
}
#[derive(Serialize)]
pub struct RsShortInvite {
    retval: bool,
    invite: String,
}
#[post("/GetShortInvite")]
pub async fn rs_peers_get_short_invite(
    _state: web::Data<Arc<DataCore>>,
    _format_radix: web::Json<FormatRadix>,
) -> Result<impl Responder> {
    Ok(web::Json(RsShortInvite {
        retval: true,
        invite: String::from("https://me.retroshare.cc?rsInvite=123456789_THIS_IS_A_DUMMY"),
    }))
}

// rsPeers/getFriendList
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FriendList {
    retval: bool,
    ssl_ids: Vec<SslIdHex>,
}
#[post("/getFriendList")]
pub async fn rs_peers_get_friend_list(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    let ssl_ids = state
        .get_locations()
        .into_iter()
        .map(|loc| *loc.get_location_id())
        .map(|id| id.into())
        .collect();

    Ok(web::Json(FriendList {
        retval: true,
        ssl_ids,
    }))
}

// rsPeers/getPeerDetails (with the network fields of RsPeerDetails from peers.cfg:
// localAddr, localPort, extAddr, extPort, dyndns, netMode, vs_disc, vs_dht)
#[post("/getPeerDetails")]
pub async fn rs_peers_get_peer_details(
    state: web::Data<Arc<DataCore>>,
    ssl_id: web::Json<SslIdWrapped>,
) -> Result<impl Responder> {
    let id = *ssl_id.0;
    let Some(loc) = state.get_location_by_id(Arc::new(id)) else {
        return Ok(web::Json(serde_json::json!({ "retval": false })));
    };
    let mut det = serde_json::to_value(loc.get_peer_details()).unwrap_or_default();
    if let (Some(item), Some(obj)) = (state.get_peers_cfg_item(&id).await, det.as_object_mut()) {
        let local = item.local_addr_v4.0;
        let ext = item.ext_addr_v4.0;
        obj.insert("localAddr".into(), local.ip().to_string().into());
        obj.insert("localPort".into(), local.port().into());
        obj.insert("extAddr".into(), ext.ip().to_string().into());
        obj.insert("extPort".into(), ext.port().into());
        obj.insert("dyndns".into(), item.dyndns.to_string().into());
        obj.insert("netMode".into(), item.net_mode.into());
        obj.insert("vs_disc".into(), item.vs_disc.into());
        obj.insert("vs_dht".into(), item.vs_dht.into());
    }
    Ok(web::Json(serde_json::json!({ "retval": true, "det": det })))
}

// rsPeers/setLocalAddress, setExtAddress
//  virtual bool setLocalAddress(const RsPeerId &ssl_id, const std::string &addr, uint16_t port) = 0;
//  virtual bool setExtAddress(const RsPeerId &ssl_id, const std::string &addr, uint16_t port) = 0;
#[derive(Deserialize)]
pub struct SetAddressParam {
    #[serde(rename = "sslId")]
    ssl_id: SslIdHex,
    addr: String,
    port: u16,
}
async fn change_item<F>(state: &DataCore, ssl_id: &SslIdHex, change: F) -> bool
where
    F: FnOnce(&mut retroshare_compat::config::PeerNetItem) -> bool,
{
    let Some(mut item) = state.get_peers_cfg_item(ssl_id).await else {
        return false;
    };
    if !change(&mut item) {
        return false;
    }
    match state.update_peers_cfg(item).await {
        Ok(()) => true,
        Err(err) => {
            log::warn!("can't save peers.cfg: {err}");
            false
        }
    }
}
fn parse_addr(addr: &str, port: u16) -> Option<std::net::SocketAddr> {
    let ip: std::net::IpAddr = addr.trim().parse().ok()?;
    Some(std::net::SocketAddr::new(ip, port))
}
#[post("/setLocalAddress")]
pub async fn rs_peers_set_local_address(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SetAddressParam>,
) -> Result<impl Responder> {
    let addr = parse_addr(&params.addr, params.port);
    let ok = match addr {
        Some(addr) => change_item(&state, &params.ssl_id, |i| {
            i.local_addr_v4 = retroshare_compat::tlv::tlv_ip_addr::TlvIpAddress(addr);
            true
        })
        .await,
        None => false,
    };
    Ok(web::Json(RetVal { retval: ok }))
}
#[post("/setExtAddress")]
pub async fn rs_peers_set_ext_address(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SetAddressParam>,
) -> Result<impl Responder> {
    let addr = parse_addr(&params.addr, params.port);
    let ok = match addr {
        Some(addr) => change_item(&state, &params.ssl_id, |i| {
            i.ext_addr_v4 = retroshare_compat::tlv::tlv_ip_addr::TlvIpAddress(addr);
            true
        })
        .await,
        None => false,
    };
    Ok(web::Json(RetVal { retval: ok }))
}

// rsPeers/setDynDNS
//  virtual bool setDynDNS(const RsPeerId &id, const std::string &addr) = 0;
#[derive(Deserialize)]
pub struct SetDynDnsParam {
    id: SslIdHex,
    addr: String,
}
#[post("/setDynDNS")]
pub async fn rs_peers_set_dyndns(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SetDynDnsParam>,
) -> Result<impl Responder> {
    let addr = params.addr.trim().to_owned();
    let ok = change_item(&state, &params.id, |i| {
        i.dyndns = addr.into();
        true
    })
    .await;
    Ok(web::Json(RetVal { retval: ok }))
}

// rsPeers/setNetworkMode
//  virtual bool setNetworkMode(const RsPeerId &ssl_id, uint32_t netMode) = 0;
//  RS_NETMODE_UDP 1 (firewalled), RS_NETMODE_UPNP 2, RS_NETMODE_EXT 3 (manually forwarded)
#[derive(Deserialize)]
pub struct SetNetworkModeParam {
    #[serde(rename = "sslId")]
    ssl_id: SslIdHex,
    #[serde(rename = "netMode")]
    net_mode: u32,
}
#[post("/setNetworkMode")]
pub async fn rs_peers_set_network_mode(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SetNetworkModeParam>,
) -> Result<impl Responder> {
    let mode = params.net_mode;
    let ok = (1..=3).contains(&mode)
        && change_item(&state, &params.ssl_id, |i| {
            i.net_mode = mode;
            true
        })
        .await;
    Ok(web::Json(RetVal { retval: ok }))
}

// rsPeers/setVisState
//  virtual bool setVisState(const RsPeerId &ssl_id, uint16_t vs_disc, uint16_t vs_dht) = 0;
//  RS_VS_DISC_OFF 0 / MINIMAL 1 / FULL 2, RS_VS_DHT_OFF 0 / PASSIVE 1 / FULL 2
#[derive(Deserialize)]
pub struct SetVisStateParam {
    #[serde(rename = "sslId")]
    ssl_id: SslIdHex,
    vs_disc: u16,
    vs_dht: u16,
}
#[post("/setVisState")]
pub async fn rs_peers_set_vis_state(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SetVisStateParam>,
) -> Result<impl Responder> {
    let (disc, dht) = (params.vs_disc, params.vs_dht);
    let ok = disc <= 2
        && dht <= 2
        && change_item(&state, &params.ssl_id, |i| {
            i.vs_disc = disc;
            i.vs_dht = dht;
            true
        })
        .await;
    Ok(web::Json(RetVal { retval: ok }))
}

// rsPeers/getAllowServerIPDetermination, rsPeers/allowServerIPDetermination
#[post("/getAllowServerIPDetermination")]
pub async fn rs_peers_get_allow_server_ip(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    Ok(web::Json(RetVal {
        retval: state.get_ip_finder().await,
    }))
}
#[derive(Deserialize)]
pub struct AllowServerIpParam {
    active: bool,
}
#[post("/allowServerIPDetermination")]
pub async fn rs_peers_allow_server_ip(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<AllowServerIpParam>,
) -> Result<impl Responder> {
    let ok = match state.set_ip_finder(params.active).await {
        Ok(()) => true,
        Err(err) => {
            log::warn!("can't save peers.cfg: {err}");
            false
        }
    };
    Ok(web::Json(RetVal { retval: ok }))
}

// rsPeers/isOnline
#[derive(Serialize)]
pub struct IsOnline {
    retval: bool,
}
#[post("/isOnline")]
pub async fn rs_peers_is_online(
    state: web::Data<Arc<DataCore>>,
    ssl_id: web::Json<SslIdWrapped>,
) -> Result<impl Responder> {
    let online = state.is_online(Arc::new(*ssl_id.0)).await;
    Ok(web::Json(RetVal { retval: online }))
}

// rsPeers/removeFriendLocation, like RetroShare: {"sslId": "..."} -> {"retval": bool}
// (rustyshare also returns "errorMessage" when it fails)
#[post("/removeFriendLocation")]
pub async fn rs_peers_remove_friend_location(
    state: web::Data<Arc<DataCore>>,
    ssl_id: web::Json<SslIdWrapped>,
) -> Result<impl Responder> {
    Ok(web::Json(match state.remove_friend(&*ssl_id.0).await {
        Ok(who) => {
            log::info!("removed friend {who}");
            AcceptInviteResult {
                retval: true,
                error_message: String::new(),
            }
        }
        Err(err) => {
            log::warn!("failed to remove friend {}: {err}", *ssl_id.0);
            AcceptInviteResult {
                retval: false,
                error_message: err,
            }
        }
    }))
}

// rsPeers/getFriendsOverview (rustyshare specific): friends with their locations,
// online state, last seen and connection address
#[post("/getFriendsOverview")]
pub async fn rs_peers_get_friends_overview(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    Ok(web::Json(RetVal {
        retval: state.get_friends_overview().await,
    }))
}

// rsPeers/getFriendsOfFriends (rustyshare specific): locations our friends know
#[post("/getFriendsOfFriends")]
pub async fn rs_peers_get_friends_of_friends(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    Ok(web::Json(RetVal {
        retval: state.get_friends_of_friends(),
    }))
}

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsPeers")
        .service(rs_peers_get_peer_details)
        .service(rs_peers_is_online)
        .service(rs_peers_get_friend_list)
        .service(rs_peers_get_rs_invite)
        .service(rs_peers_get_short_invite)
        .service(rs_peers_accept_invite)
        .service(rs_peers_get_friends_of_friends)
        .service(rs_peers_remove_friend_location)
        .service(rs_peers_get_friends_overview)
        .service(rs_peers_set_local_address)
        .service(rs_peers_set_ext_address)
        .service(rs_peers_set_dyndns)
        .service(rs_peers_set_network_mode)
        .service(rs_peers_set_vis_state)
        .service(rs_peers_get_allow_server_ip)
        .service(rs_peers_allow_server_ip)
}
