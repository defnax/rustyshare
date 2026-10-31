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

// rsPeers/getPeerDetails
#[derive(Serialize)]
pub struct PeerDetails {
    retval: bool,
    det: ::retroshare_compat::peers::PeerDetails,
}
#[post("/getPeerDetails")]
pub async fn rs_peers_get_peer_details(
    state: web::Data<Arc<DataCore>>,
    ssl_id: web::Json<SslIdWrapped>,
) -> Result<impl Responder> {
    Ok(web::Json(PeerDetails {
        retval: true,
        det: state
            .get_location_by_id(Arc::new(*ssl_id.0))
            .unwrap()
            .get_peer_details(),
    }))
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
}
