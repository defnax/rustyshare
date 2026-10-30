// #![warn(
//     clippy::await_holding_lock,
//     clippy::cargo_common_metadata,
//     clippy::dbg_macro,
//     clippy::empty_enum,
//     clippy::enum_glob_use,
//     clippy::inefficient_to_string,
//     clippy::mem_forget,
//     clippy::mutex_integer,
//     clippy::needless_continue,
//     clippy::todo,
//     clippy::unimplemented,
//     clippy::wildcard_imports,
//     future_incompatible,
//     // missing_docs,
//     missing_debug_implementations,
//     unreachable_pub
// )]

use controller::CoreController;
use log::warn;
use std::{
    convert::TryInto,
    fs::File,
    io::{self, Read},
    path::Path,
    sync::Arc,
};
use colored::Colorize;
use tokio::select;
// use tracing_log::trace_logger;
// use tokio::{self, select};

use ::retroshare_compat::basics::*;

mod controller;
mod error;
mod gxs;
#[allow(unused_imports)]
mod log_internal;
mod low_level_parsing;
mod model;
mod profile;
mod retroshare_compat;
mod serial_stuff;
mod services;
mod transport_ng;
mod utils;
mod webui;

use ::retroshare_compat::keyring::Keyring;
use io::Write;
use openssl::x509::X509;
use sequoia_openpgp as openpgp;

#[allow(unused_braces)]
fn read_location_cert(path: &Path) -> Result<X509, io::Error> {
    // fn read_location_cert(path: &Path) -> Result<Certificate, RsError> {
    let full_path = path.join("keys/user_cert.pem");
    let mut file = File::open(full_path)?;

    let mut user_cert = Vec::new();
    file.read_to_end(&mut user_cert)?;

    Ok(openssl::x509::X509::from_pem(&user_cert)?)
}

enum Selection {
    Location((String, X509, openpgp::cert::Cert)),
    CreateNew,
    Invalid,
}

#[allow(unused_braces)]
fn select_location(base_dir: &Path, keys: &Keyring) -> Selection {
    const LOC_FOLDER_PREFIX: &str = "LOC06_";
    const LOC_FOLDER_PREFIX_HIDDEN: &str = "HID06_";

    // build list with valid options
    let mut locations = vec![];
    // let mut locations: Vec<(String, Certificate, Cert)> = vec![];
    std::fs::create_dir_all(base_dir).expect("failed to create RetroShare folder");
    for dir in std::fs::read_dir(base_dir).expect("failed to list folder") {
        // get folder (name)
        let dir = dir.unwrap();
        let dir_name = dir.file_name().to_string_lossy().to_string();

        // check if it's a valid candidate
        if dir_name.len() != 38
            || (!dir_name.starts_with(LOC_FOLDER_PREFIX)
                && !dir_name.starts_with(LOC_FOLDER_PREFIX_HIDDEN))
        {
            continue;
        }

        // read pub key
        let cert = read_location_cert(&dir.path());
        if cert.is_err() {
            // TODO Add error handling
            continue;
        }
        let cert = cert.unwrap();

        // find priv key
        let key = keys.get_key_by_id_str(
            &String::from_utf8_lossy(
                cert
                    // .0
                    .issuer_name()
                    .entries()
                    .into_iter()
                    .next()
                    .unwrap()
                    .data()
                    .as_slice(),
            ),
            true,
        );
        if key.is_none() {
            // TODO Add error handling
            continue;
        }
        let key = key.unwrap().to_owned();

        // TODO
        // figure out the actual location name

        locations.push((dir_name, cert, key));
    }

    // nothing there yet -> create a profile
    if locations.is_empty() {
        println!(
            "{} {}",
            "No location found in".yellow(),
            base_dir.display().to_string().yellow()
        );
        return Selection::CreateNew;
    }

    // ask user
    println!("{}", "Please select a location:".green().bold());
    let mut num = 1;
    for loc in &locations {
        let name = loc.2.userids().next().unwrap().to_string();
        let loc_name = std::fs::read_to_string(base_dir.join(&loc.0).join("keys/location_name.txt"))
            .unwrap_or_default();
        println!(
            " [{}]: {} - '{}' ({})",
            num.to_string().yellow(),
            loc_name.trim().cyan().bold(),
            name.green(),
            loc.0.dimmed()
        );
        num += 1;
    }
    println!(" [{}]: create a new location / profile", "n".yellow());
    print!("{}", "> ".cyan());
    io::stdout().flush().unwrap();

    // read answer and return the entry
    let mut buffer = String::new();
    match io::stdin().read_line(&mut buffer) {
        Ok(_) => {
            let buffer = buffer.trim();
            if buffer.eq_ignore_ascii_case("n") {
                return Selection::CreateNew;
            }

            // parse number
            let num_selected = match buffer.parse::<usize>() {
                Ok(n) if n >= 1 && n <= locations.len() => n,
                _ => {
                    warn!("invalid selection");
                    return Selection::Invalid;
                }
            };

            // get key
            let loc = &locations[num_selected - 1];
            return Selection::Location(loc.to_owned());
        }
        Err(err) => warn!("failed {err}"),
    }
    Selection::Invalid
}

/// Builds the friend list for a location without peers.cfg: just ourself.
fn own_peer_only(
    pgp: &openpgp::cert::Cert,
    location_path: &Path,
    ssl_id: Arc<SslId>,
) -> (Vec<Arc<model::person::Peer>>, Vec<Arc<model::location::Location>>) {
    let name = pgp
        .userids()
        .next()
        .map(|u| String::from_utf8_lossy(u.userid().value()).to_string())
        .unwrap_or_default();
    let location_name = std::fs::read_to_string(location_path.join("keys/location_name.txt"))
        .unwrap_or_else(|_| "My computer".into());
    let pgp_id = PgpId(
        pgp.keyid()
            .as_bytes()
            .try_into()
            .expect("PGP key id is not 8 bytes"),
    );
    let public = pgp.clone().strip_secret_key_material();

    let person = Arc::new(model::person::Peer::new(name, public, pgp_id));
    let location = Arc::new(model::location::Location::new(
        location_name,
        ssl_id,
        Arc::new(pgp_id),
        (vec![], vec![]),
        person.clone(),
    ));
    person.add_location(location.clone());
    (vec![person], vec![location])
}

#[tokio::main]
async fn main() {
    // enable ANSI colors in the Windows terminal
    #[cfg(windows)]
    colored::control::set_virtual_terminal(true).ok();

    log_internal::init_logger();

    let rs_base_dir = retroshare_compat::get_base_dir();

    // load keyring
    let mut keys = Keyring::new();
    keys.parse(&rs_base_dir);

    let (loc, location_path, ssl_key, (gxs_id_db, _gxs_forum_db)) = loop {
        // pick location
        let loc = match select_location(&rs_base_dir, &keys) {
            Selection::Location(a) => a,
            Selection::Invalid => continue,
            Selection::CreateNew => {
                profile::create_interactive(&rs_base_dir, &keys);
                // reload keyring, the new profile may have been added
                keys.parse(&rs_base_dir);
                continue;
            }
        };
        let location_path = rs_base_dir.join(&loc.0);

        println!("");
        let mut password =
            rpassword::prompt_password_stdout(&"Password: ".cyan().to_string()).unwrap();

        // unlock key ...
        match retroshare_compat::ssl_key::SslKey::new().load_encrypted(
            &loc.2,
            &location_path,
            &password,
        ) {
            Ok((key, gxs)) => {
                password.clear();
                break (loc, location_path, key, gxs);
            }
            Err(why) => {
                warn!("{}", why);
            }
        }
        password.clear();

        // try again!
        println!("{}\n", "... failed! (wrong password?)".red().bold());
    };

    // ... load general config ...
    // (newer RetroShare profiles may not have a general.cfg yet, it's optional)
    let general_cfg_path = location_path.join("config/general.cfg");
    if general_cfg_path.exists() {
        match retroshare_compat::config_store::decrypt_file(&general_cfg_path, ssl_key.to_owned())
        {
            Ok(mut general_cfg) => serial_stuff::parse_general_cfg(&mut general_cfg),
            Err(err) => warn!("failed to load general.cfg: {err}"),
        }
    } else {
        warn!("no general.cfg found, skipping");
    }

    // ... and load location ...
    // build own id
    let hex = hex::decode(&loc.0[6..]).expect("Decoding failed");
    let peer_id: [u8; 16] = hex.try_into().expect("failed to convert!"); // SSL_ID
    let peer_id = Arc::new(SslId(peer_id));

    // ... and peer infos (a freshly created location has no peers.cfg yet)
    let peers_cfg_path = location_path.join("config/peers.cfg");
    let friends = if peers_cfg_path.exists() {
        let mut peers_cfg =
            retroshare_compat::config_store::decrypt_file(&peers_cfg_path, ssl_key.to_owned())
                .expect("failed to load peers.cfg");
        serial_stuff::load_peers(&mut peers_cfg, &keys)
    } else {
        warn!("no peers.cfg found (new location?), starting with no friends");
        own_peer_only(&loc.2, &location_path, peer_id.clone())
    };

    // init data core
    // let data_core = model::DataCore::new(ssl_key, friends, peer_id).await;

    // enter main loop
    let (mut core, data_core) = CoreController::new(ssl_key, friends, peer_id, gxs_id_db).await;
    let fut = core.run();

    // let own_ips = data_core.get_own_location().get_ips().0.clone(); // TODO

    // setup listener
    // let port = own_ips
    //     .iter()
    //     .find(|ip| {
    //         if let SocketAddr::V4(v4) = ip.addr.0 {
    //             return v4.ip().is_private();
    //         }
    //         false
    //     })
    //     .expect("can't find local address!")
    //     .addr
    //     .0
    //     .port();
    // let _addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);

    // setup webui
    let web = webui::actix::run_actix(data_core.clone());

    // run everything
    select! {
        _ = web => {},
        _ = fut => {},
    }
}
