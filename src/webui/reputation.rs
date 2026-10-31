//! rsReputations JSON API, names and parameters as in libretroshare's
//! retroshare/rsreputations.h.

use std::sync::Arc;

use actix_web::{post, web, Responder, Result};
use serde::{Deserialize, Serialize};

use crate::{model::DataCore, webui::RetVal};

#[derive(Deserialize)]
pub struct IdParam {
    id: String,
}

#[derive(Deserialize)]
pub struct SetOwnOpinionParam {
    id: String,
    /// RsOpinion: 0 negative, 1 neutral, 2 positive
    op: u8,
}

fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit())
}

// rsReputations/setOwnOpinion
#[post("/setOwnOpinion")]
pub async fn rs_reputations_set_own_opinion(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SetOwnOpinionParam>,
) -> Result<impl Responder> {
    let ok = valid_id(&params.id) && params.op <= crate::reputation::OPINION_POSITIVE;
    if ok {
        state.reputation_set_own(&params.id, params.op);
        log::info!("own opinion about {} set to {}", params.id, params.op);
    }
    Ok(web::Json(RetVal { retval: ok }))
}

// rsReputations/getOwnOpinion
#[derive(Serialize)]
pub struct OwnOpinionOut {
    retval: bool,
    op: u8,
}
#[post("/getOwnOpinion")]
pub async fn rs_reputations_get_own_opinion(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<IdParam>,
) -> Result<impl Responder> {
    let ok = valid_id(&params.id);
    let op = if ok {
        state.reputation_info(&params.id, false, false).own_opinion
    } else {
        crate::reputation::OPINION_NEUTRAL
    };
    Ok(web::Json(OwnOpinionOut { retval: ok, op }))
}

// rsReputations/getReputationInfo
#[derive(Deserialize)]
pub struct ReputationInfoParam {
    id: String,
    /// PGP id of a signed identity's owner, may be empty / all zero
    #[serde(default, rename = "ownerNode")]
    owner_node: String,
}
#[derive(Serialize)]
pub struct ReputationInfoOut {
    retval: bool,
    info: crate::reputation::ReputationInfo,
}
#[post("/getReputationInfo")]
pub async fn rs_reputations_get_reputation_info(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<ReputationInfoParam>,
) -> Result<impl Responder> {
    let owner = params.owner_node.trim().to_lowercase();
    let linked = !owner.is_empty() && owner.chars().any(|c| c != '0');
    let known = linked
        && state
            .get_persons()
            .iter()
            .any(|p| p.get_pgp_id().to_string().to_lowercase() == owner);
    Ok(web::Json(ReputationInfoOut {
        retval: valid_id(&params.id),
        info: state.reputation_info(&params.id, linked, known),
    }))
}

// rsReputations/overallReputationLevel
#[post("/overallReputationLevel")]
pub async fn rs_reputations_overall_level(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<IdParam>,
) -> Result<impl Responder> {
    Ok(web::Json(RetVal {
        retval: state.reputation_info(&params.id, false, false).overall_level,
    }))
}

// rsReputations/isIdentityBanned
#[post("/isIdentityBanned")]
pub async fn rs_reputations_is_identity_banned(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<IdParam>,
) -> Result<impl Responder> {
    Ok(web::Json(RetVal {
        retval: state.reputation_is_banned(&params.id),
    }))
}

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsReputations")
        .service(rs_reputations_set_own_opinion)
        .service(rs_reputations_get_own_opinion)
        .service(rs_reputations_get_reputation_info)
        .service(rs_reputations_overall_level)
        .service(rs_reputations_is_identity_banned)
}
