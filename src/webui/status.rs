//! rsStatus JSON API, names and parameters as in libretroshare's
//! retroshare/rsstatus.h (see presence.rs).

use std::sync::Arc;

use actix_web::{post, web, Responder, Result};
use serde::{Deserialize, Serialize};

use crate::{model::DataCore, presence::STATUS_OFFLINE, webui::RetVal};

/// StatusInfo
#[derive(Serialize)]
pub struct StatusInfo {
    id: String,
    /// RsStatusValue: 0 offline, 1 away, 2 busy, 3 online, 4 inactive
    status: u32,
    /// for us the time it was set, for friends the time they sent it
    time_stamp: u64,
}

#[derive(Serialize)]
pub struct StatusOut {
    retval: bool,
    #[serde(rename = "statusInfo")]
    status_info: StatusInfo,
}

#[derive(Serialize)]
pub struct StatusListOut {
    retval: bool,
    #[serde(rename = "statusInfo")]
    status_info: Vec<StatusInfo>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn own_info(state: &DataCore) -> StatusInfo {
    let own = state.own_presence();
    StatusInfo {
        id: state.get_own_location().get_location_id().to_string(),
        status: own.status,
        time_stamp: own.time_stamp,
    }
}

async fn peer_info(state: &DataCore, id: &str) -> StatusInfo {
    let p = state.presence_of_peer(id);
    let online = state
        .get_connected_peers()
        .lock()
        .await
        .0
        .keys()
        .any(|k| k.to_string() == id);
    StatusInfo {
        id: id.to_owned(),
        status: if online { p.effective_status() } else { STATUS_OFFLINE },
        time_stamp: p.time_stamp,
    }
}

// rsStatus/getOwnStatus
//  virtual bool getOwnStatus(StatusInfo& statusInfo) = 0;
#[post("/getOwnStatus")]
pub async fn rs_status_get_own_status(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    Ok(web::Json(StatusOut {
        retval: true,
        status_info: own_info(&state),
    }))
}

// rsStatus/getStatusList
//  virtual bool getStatusList(std::list<StatusInfo>& statusInfo) = 0;
#[post("/getStatusList")]
pub async fn rs_status_get_status_list(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    let own = state.get_own_location().get_location_id();
    let mut list = vec![];
    for loc in state.get_locations() {
        let id = loc.get_location_id();
        if id != own {
            list.push(peer_info(&state, &id.to_string()).await);
        }
    }
    Ok(web::Json(StatusListOut {
        retval: true,
        status_info: list,
    }))
}

// rsStatus/getStatus
//  virtual bool getStatus(const RsPeerId &id, StatusInfo &statusInfo) = 0;
#[derive(Deserialize)]
pub struct IdParam {
    id: String,
}
#[post("/getStatus")]
pub async fn rs_status_get_status(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<IdParam>,
) -> Result<impl Responder> {
    let id = params.id.trim().to_lowercase();
    let info = if id == state.get_own_location().get_location_id().to_string() {
        own_info(&state)
    } else {
        peer_info(&state, &id).await
    };
    Ok(web::Json(StatusOut {
        retval: true,
        status_info: info,
    }))
}

// rsStatus/sendStatus
//  virtual bool sendStatus(const RsPeerId &id, RsStatusValue status) = 0;
//  id: the peer to send the status to (empty: send to all)
#[derive(Deserialize)]
pub struct SendStatusParam {
    #[serde(default)]
    id: String,
    status: u32,
}
#[post("/sendStatus")]
pub async fn rs_status_send_status(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SendStatusParam>,
) -> Result<impl Responder> {
    let id = params.id.trim().to_lowercase();
    let own = state.get_own_location().get_location_id().to_string();
    let to = if id.is_empty() || id.chars().all(|c| c == '0') || id == own {
        None
    } else {
        Some(id)
    };
    Ok(web::Json(RetVal {
        retval: state.set_own_status(params.status, to).await,
    }))
}

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsStatus")
        .service(rs_status_get_own_status)
        .service(rs_status_get_status_list)
        .service(rs_status_get_status)
        .service(rs_status_send_status)
}
