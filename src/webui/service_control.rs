//! rsServiceControl: service permissions (Settings → Services), like RetroShare's
//! JSON API. See `service_control.rs`.

use std::{collections::BTreeMap, sync::Arc};

use actix_web::{post, web, Responder, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{model::DataCore, service_control};

/// std::map<uint32_t, RsServiceInfo> as RetroShare's JSON API writes it
fn service_list(list: &BTreeMap<u32, String>) -> Value {
    Value::Array(
        list.iter()
            .map(|(id, name)| {
                json!({ "key": id, "value": {
                    "mServiceName": name, "mServiceType": id,
                    "mVersionMajor": 1, "mVersionMinor": 0,
                    "mMinVersionMajor": 1, "mMinVersionMinor": 0,
                }})
            })
            .collect(),
    )
}

fn parse_peer(hex_id: &str) -> Option<service_control::Id> {
    hex::decode(hex_id.trim()).ok()?.try_into().ok()
}

// rsServiceControl/getOwnServices
#[post("/getOwnServices")]
pub async fn get_own_services(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    let own = state.get_own_location().get_location_id().to_string();
    Ok(web::Json(json!({ "retval": true, "info": {
        "mPeerId": own, "mServiceList": service_list(&service_control::own_services()) } })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerIn {
    peer_id: String,
}

// rsServiceControl/getServicesProvided {peerId}: what the friend announced
#[post("/getServicesProvided")]
pub async fn get_services_provided(params: web::Json<PeerIn>) -> Result<impl Responder> {
    let Some(peer) = parse_peer(&params.peer_id) else {
        return Ok(web::Json(json!({ "retval": false })));
    };
    let list = service_control::provided(&peer);
    Ok(web::Json(json!({ "retval": true, "info": {
        "mPeerId": params.peer_id.trim(), "mServiceList": service_list(&list) } })))
}

// rsServiceControl/getServicesAllowed {peerId}: what we announce to the friend
#[post("/getServicesAllowed")]
pub async fn get_services_allowed(params: web::Json<PeerIn>) -> Result<impl Responder> {
    let Some(peer) = parse_peer(&params.peer_id) else {
        return Ok(web::Json(json!({ "retval": false })));
    };
    let list: BTreeMap<u32, String> = service_control::own_services()
        .into_iter()
        .filter(|(id, _)| service_control::allowed(&peer, (id >> 8) as u16))
        .collect();
    Ok(web::Json(json!({ "retval": true, "info": {
        "mPeerId": params.peer_id.trim(), "mServiceList": service_list(&list) } })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceIn {
    service_id: u32,
}

// rsServiceControl/getServicePermissions {serviceId}
#[post("/getServicePermissions")]
pub async fn get_service_permissions(params: web::Json<ServiceIn>) -> Result<impl Responder> {
    Ok(web::Json(match service_control::permissions(params.service_id) {
        Some(p) => json!({ "retval": true, "permissions": {
            "mServiceId": p.service_id,
            "mServiceName": p.name,
            "mDefaultAllowed": p.default_allowed,
            "mPeersAllowed": p.allowed.iter().map(hex::encode).collect::<Vec<_>>(),
            "mPeersDenied": p.denied.iter().map(hex::encode).collect::<Vec<_>>(),
        }}),
        None => json!({ "retval": false }),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionsJson {
    #[serde(default)]
    m_service_name: String,
    m_default_allowed: bool,
    #[serde(default)]
    m_peers_allowed: Vec<String>,
    #[serde(default)]
    m_peers_denied: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateIn {
    service_id: u32,
    permissions: PermissionsJson,
}

// rsServiceControl/updateServicePermissions {serviceId, permissions}
#[post("/updateServicePermissions")]
pub async fn update_service_permissions(params: web::Json<UpdateIn>) -> Result<impl Responder> {
    let p = &params.permissions;
    let perms = service_control::Permissions {
        service_id: params.service_id,
        name: p.m_service_name.clone(),
        default_allowed: p.m_default_allowed,
        allowed: p.m_peers_allowed.iter().filter_map(|s| parse_peer(s)).collect(),
        denied: p.m_peers_denied.iter().filter_map(|s| parse_peer(s)).collect(),
    };
    let retval = service_control::update(params.service_id, perms);
    Ok(web::Json(json!({ "retval": retval })))
}

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsServiceControl")
        .service(get_own_services)
        .service(get_services_provided)
        .service(get_services_allowed)
        .service(get_service_permissions)
        .service(update_service_permissions)
}
