//! Settings page: rsConfig (bandwidth limits, names as in retroshare/rsconfig.h) and
//! rustyshare's own settings.

use std::sync::Arc;

use actix_web::{post, web, Responder, Result};
use serde::{Deserialize, Serialize};

use crate::{model::DataCore, webui::RetVal};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataRatesOut {
    retval: i32,
    in_kb: f32,
    out_kb: f32,
}

// rsConfig/GetMaxDataRates
//  virtual int GetMaxDataRates( int &inKb, int &outKb) = 0;
#[post("/GetMaxDataRates")]
pub async fn rs_config_get_max_data_rates() -> Result<impl Responder> {
    Ok(web::Json(DataRatesOut {
        retval: 1,
        in_kb: crate::bandwidth::down().rate().round(),
        out_kb: crate::bandwidth::up().rate().round(),
    }))
}

// rsConfig/SetMaxDataRates
//  virtual int SetMaxDataRates( int downKb, int upKb) = 0;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRatesParam {
    down_kb: i32,
    up_kb: i32,
}
#[post("/SetMaxDataRates")]
pub async fn rs_config_set_max_data_rates(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<SetRatesParam>,
) -> Result<impl Responder> {
    let ok = state.set_max_data_rates(params.down_kb as f32, params.up_kb as f32);
    Ok(web::Json(RetVal {
        retval: if ok { 1 } else { 0 },
    }))
}

// rsConfig/GetCurrentDataRates
//  virtual int GetCurrentDataRates( float &inKb, float &outKb ) = 0;
#[post("/GetCurrentDataRates")]
pub async fn rs_config_get_current_data_rates() -> Result<impl Responder> {
    Ok(web::Json(DataRatesOut {
        retval: 1,
        in_kb: crate::bandwidth::down().current_kb(),
        out_kb: crate::bandwidth::up().current_kb(),
    }))
}

pub fn get_rs_config_entry_points() -> actix_web::Scope {
    web::scope("/rsConfig")
        .service(rs_config_get_max_data_rates)
        .service(rs_config_set_max_data_rates)
        .service(rs_config_get_current_data_rates)
}

// rustyshare/getSettings, rustyshare/setSettings, rustyshare/clearChatHistory
#[derive(Serialize)]
pub struct SettingsOut {
    retval: crate::settings::Settings,
    version: &'static str,
    /// the location's folder
    data_dir: String,
}
#[post("/getSettings")]
pub async fn rustyshare_get_settings(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    let config = state.get_config_dir().await;
    let data_dir = config.parent().unwrap_or(&config).display().to_string();
    Ok(web::Json(SettingsOut {
        retval: state.get_settings(),
        version: env!("CARGO_PKG_VERSION"),
        data_dir,
    }))
}

#[post("/setSettings")]
pub async fn rustyshare_set_settings(
    state: web::Data<Arc<DataCore>>,
    params: web::Json<crate::settings::Settings>,
) -> Result<impl Responder> {
    state.set_settings(params.into_inner()).await;
    Ok(web::Json(RetVal { retval: true }))
}

#[post("/clearChatHistory")]
pub async fn rustyshare_clear_chat_history(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    state.clear_chat_history();
    log::info!("chat history cleared");
    Ok(web::Json(RetVal { retval: true }))
}
