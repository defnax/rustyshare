//! Service permissions, like RetroShare's p3ServiceControl ("Permissions" in the
//! settings): every service can be switched on or off for all friends, with
//! exceptions per friend.
//!
//! - We only announce (service info, 0x0020) the services a friend may use, so
//!   RetroShare on the other side stops using the others too.
//! - Packets of a service the friend may not use are dropped in both directions.
//! - The service info service itself always passes ("or we have nothing").
//!
//! Stored like RetroShare in `config/servicecontrol.cfg` (RsServicePermissionItem,
//! service 0x0026, sub type 0x01), so both programs share the setting.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
    sync::{OnceLock, RwLock},
};

use byteorder::{ByteOrder, NetworkEndian};
use log::{info, warn};
use retroshare_compat::services::service_info::RsServiceInfo;
use tokio::sync::watch;

use crate::retroshare_compat::{config_store, ssl_key::SslKey};

const FILE: &str = "servicecontrol.cfg";
const HEADER_SIZE: usize = 8;
/// version SERVICE (0x02), service SERVICE_CONTROL (0x0026), sub type SERVICE_PERMISSIONS (0x01)
const PERMISSION_HEADER: [u8; 4] = [0x02, 0x00, 0x26, 0x01];
const TLV_TYPE_STR_NAME: u16 = 0x0051;
/// RS_SERVICE_TYPE_SERVICEINFO, always allowed
const SERVICE_INFO: u16 = 0x0020;

pub type Id = [u8; 16];

/// RsServicePermissions
#[derive(Debug, Clone, Default)]
pub struct Permissions {
    pub service_id: u32,
    pub name: String,
    /// true: everybody except `denied`; false: nobody except `allowed`
    pub default_allowed: bool,
    pub allowed: BTreeSet<Id>,
    pub denied: BTreeSet<Id>,
}

impl Permissions {
    /// RsServicePermissions::peerHasPermission()
    pub fn peer_allowed(&self, peer: &Id) -> bool {
        if self.default_allowed {
            !self.denied.contains(peer)
        } else {
            self.allowed.contains(peer)
        }
    }
}

struct State {
    path: PathBuf,
    keys: SslKey,
    writable: bool,
    perms: BTreeMap<u32, Permissions>,
    /// items we don't know, written back unchanged
    other_items: Vec<Vec<u8>>,
    /// our services (full id -> name)
    own: BTreeMap<u32, String>,
    /// services announced by friends' locations
    provided: HashMap<Id, BTreeMap<u32, String>>,
}

static STATE: OnceLock<RwLock<State>> = OnceLock::new();
/// bumped on every change, the connections resend their service list
static CHANGED: OnceLock<watch::Sender<u64>> = OnceLock::new();

fn changed() -> &'static watch::Sender<u64> {
    CHANGED.get_or_init(|| watch::channel(0).0)
}

/// Connections wait on this to announce a new service list.
pub fn subscribe() -> watch::Receiver<u64> {
    changed().subscribe()
}

pub fn full_id(service: u16) -> u32 {
    (0x02u32 << 24) | ((service as u32) << 8)
}

pub fn load(config_dir: PathBuf, keys: &SslKey) {
    let path = config_dir.join(FILE);
    let mut state = State {
        path,
        keys: keys.clone(),
        writable: true,
        perms: BTreeMap::new(),
        other_items: vec![],
        own: BTreeMap::new(),
        provided: HashMap::new(),
    };
    if state.path.exists() {
        match config_store::load_file(&state.path, keys) {
            Ok(data) => parse(&mut state, &data),
            Err(err) => {
                warn!("can't load {}: {err}", state.path.display());
                state.writable = false;
            }
        }
    }
    let off: Vec<_> = state
        .perms
        .values()
        .filter(|p| !p.default_allowed)
        .map(|p| p.name.clone())
        .collect();
    if !off.is_empty() {
        info!("services switched off: {}", off.join(", "));
    }
    let _ = STATE.set(RwLock::new(state));
}

fn parse(state: &mut State, data: &[u8]) {
    let mut pos = 0;
    while pos + HEADER_SIZE <= data.len() {
        let size = NetworkEndian::read_u32(&data[pos + 4..pos + 8]) as usize;
        if size < HEADER_SIZE || pos + size > data.len() {
            warn!("{FILE}: broken item at offset {pos}, not changing the file");
            state.writable = false;
            return;
        }
        let item = &data[pos..pos + size];
        pos += size;
        if item[0..4] == PERMISSION_HEADER {
            match parse_permissions(&item[HEADER_SIZE..]) {
                Some(p) => {
                    state.perms.insert(p.service_id, p);
                    continue;
                }
                None => {
                    warn!("{FILE}: can't read a permission item, not changing the file");
                    state.writable = false;
                }
            }
        }
        state.other_items.push(item.to_vec());
    }
}

fn parse_permissions(d: &[u8]) -> Option<Permissions> {
    let mut pos = 0;
    let u32_at = |pos: &mut usize| -> Option<u32> {
        let v = NetworkEndian::read_u32(d.get(*pos..*pos + 4)?);
        *pos += 4;
        Some(v)
    };
    let service_id = u32_at(&mut pos)?;
    // TLV string: u16 type, u32 size (with the 6 byte header)
    let tag = NetworkEndian::read_u16(d.get(pos..pos + 2)?);
    let len = NetworkEndian::read_u32(d.get(pos + 2..pos + 6)?) as usize;
    if tag != TLV_TYPE_STR_NAME || len < 6 {
        return None;
    }
    let name = String::from_utf8_lossy(d.get(pos + 6..pos + len)?).into_owned();
    pos += len;
    let default_allowed = *d.get(pos)? != 0;
    pos += 1;
    let mut sets = [BTreeSet::new(), BTreeSet::new()];
    for set in sets.iter_mut() {
        let n = u32_at(&mut pos)? as usize;
        for _ in 0..n {
            let id: Id = d.get(pos..pos + 16)?.try_into().ok()?;
            set.insert(id);
            pos += 16;
        }
    }
    let [allowed, denied] = sets;
    Some(Permissions {
        service_id,
        name,
        default_allowed,
        allowed,
        denied,
    })
}

fn permission_item(p: &Permissions) -> Vec<u8> {
    let mut payload = vec![];
    payload.extend(p.service_id.to_be_bytes());
    payload.extend(TLV_TYPE_STR_NAME.to_be_bytes());
    payload.extend(((p.name.len() + 6) as u32).to_be_bytes());
    payload.extend(p.name.as_bytes());
    payload.push(p.default_allowed as u8);
    for set in [&p.allowed, &p.denied] {
        payload.extend((set.len() as u32).to_be_bytes());
        for id in set {
            payload.extend(id);
        }
    }
    let mut item = PERMISSION_HEADER.to_vec();
    item.extend(((payload.len() + HEADER_SIZE) as u32).to_be_bytes());
    item.extend(payload);
    item
}

fn save(state: &State) {
    if !state.writable {
        return warn!("{FILE} could not be read, not overwriting it");
    }
    let mut data = vec![];
    for p in state.perms.values() {
        data.extend(permission_item(p));
    }
    for item in &state.other_items {
        data.extend(item);
    }
    match config_store::save_file(&state.path, &data, &state.keys) {
        Ok(()) => info!("saved {}", state.path.display()),
        Err(err) => warn!("can't save {}: {err}", state.path.display()),
    }
}

/// Our services (p3ServiceControl::registerService(): new ones are allowed for all).
pub fn register(services: &[RsServiceInfo]) {
    let Some(lock) = STATE.get() else { return };
    let mut s = lock.write().expect("lock poisoned");
    for info in services {
        s.own.insert(info.m_service_type, info.m_service_name.clone());
        s.perms.entry(info.m_service_type).or_insert_with(|| Permissions {
            service_id: info.m_service_type,
            name: info.m_service_name.clone(),
            default_allowed: true,
            ..Default::default()
        });
    }
}

/// May `peer` use `service` (16 bit service type)?
pub fn allowed(peer: &Id, service: u16) -> bool {
    if service == SERVICE_INFO {
        return true;
    }
    let Some(lock) = STATE.get() else { return true };
    let s = lock.read().expect("lock poisoned");
    s.perms
        .get(&full_id(service))
        .map(|p| p.peer_allowed(peer))
        .unwrap_or(true)
}

/// The services we announce to `peer` (p3ServiceControl::getServicesAllowed()).
pub fn filter_for(peer: &Id, services: &[RsServiceInfo]) -> Vec<RsServiceInfo> {
    services
        .iter()
        .filter(|i| allowed(peer, (i.m_service_type >> 8) as u16))
        .cloned()
        .collect()
}

/// A friend's location told us its services.
pub fn set_provided(peer: &Id, services: BTreeMap<u32, String>) {
    if let Some(lock) = STATE.get() {
        lock.write().expect("lock poisoned").provided.insert(*peer, services);
    }
}

pub fn own_services() -> BTreeMap<u32, String> {
    STATE
        .get()
        .map(|l| l.read().expect("lock poisoned").own.clone())
        .unwrap_or_default()
}

pub fn provided(peer: &Id) -> BTreeMap<u32, String> {
    STATE
        .get()
        .and_then(|l| l.read().expect("lock poisoned").provided.get(peer).cloned())
        .unwrap_or_default()
}

pub fn permissions(service_id: u32) -> Option<Permissions> {
    let lock = STATE.get()?;
    let s = lock.read().expect("lock poisoned");
    s.perms.get(&service_id).cloned()
}

/// p3ServiceControl::updateServicePermissions(): only for services we have.
pub fn update(service_id: u32, mut p: Permissions) -> bool {
    let Some(lock) = STATE.get() else { return false };
    {
        let mut s = lock.write().expect("lock poisoned");
        let Some(old) = s.perms.get(&service_id) else {
            return false;
        };
        p.service_id = service_id;
        if p.name.is_empty() {
            p.name = old.name.clone();
        }
        info!(
            "[service control] {} ({service_id:#010x}): {} for all, {} allowed, {} denied",
            p.name,
            if p.default_allowed { "on" } else { "off" },
            p.allowed.len(),
            p.denied.len()
        );
        s.perms.insert(service_id, p);
        save(&s);
    }
    changed().send_modify(|v| *v += 1);
    true
}
