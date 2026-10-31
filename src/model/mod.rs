use getset::Getters;
use log::{debug, trace, warn};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tokio::sync::{mpsc::UnboundedSender, Mutex, MutexGuard};

use retroshare_compat::{basics::SslId, events::EventType};

use crate::{
    gxs::gxs_backend::GxsShared, low_level_parsing::Packet, peers_cfg::PeersCfg,
    retroshare_compat::ssl_key::SslKey,
};

use self::{
    intercom::Intercom,
    location::Location,
    person::Peer,
    services::{chat::ChatStore, gxs_id::GxsIdStore},
};

pub mod gxs_timestamps;
pub mod intercom;
pub mod location;
pub mod person;
pub mod services;

pub struct ConnectedPeerEntries<TASK>(
    pub HashMap<Arc<SslId>, (UnboundedSender<Intercom>, tokio::task::JoinHandle<TASK>)>,
);

impl<TASK> Default for ConnectedPeerEntries<TASK> {
    fn default() -> Self {
        ConnectedPeerEntries(HashMap::new())
    }
}

#[derive(Getters)]
pub struct DataCoreServiceStore {
    #[getset(get = "pub")]
    chat: ChatStore,
    #[getset(get = "pub")]
    gxs_id: GxsIdStore,
}

impl DataCoreServiceStore {
    pub fn new(gxs_shared_id: Arc<GxsShared>) -> Self {
        DataCoreServiceStore {
            chat: ChatStore::new(),
            gxs_id: GxsIdStore::new(gxs_shared_id),
        }
    }
}

/// A location one of our friends is connected to, learned through discovery.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FriendOfFriend {
    pub ssl_id: String,
    pub pgp_id: String,
    pub location: String,
    pub addresses: Vec<String>,
    /// our friend(s) who told us
    pub via: Vec<String>,
}

pub struct DataCore {
    own_key_pair: SslKey,
    own_location: Arc<Location>,

    event_listener: Mutex<Vec<UnboundedSender<Intercom>>>,
    webui_clients: Mutex<Vec<UnboundedSender<Value>>>,

    peers: RwLock<Vec<Arc<Peer>>>,
    locations: RwLock<Vec<Arc<Location>>>,

    /// `peers.cfg` contents, saved whenever friends change
    peers_cfg: Mutex<PeersCfg>,
    /// RetroShare base folder (keyrings live here)
    base_dir: PathBuf,

    /// locations our friends told us about (discovery), that are not our friends
    friends_of_friends: RwLock<HashMap<SslId, FriendOfFriend>>,

    // gxs_dbs: Vec<Mutex<GxsDatabase>>,
    // gxs_ids: HashMap<GxsId, TlvSecurityKeySet>,
    connected_peers: Mutex<ConnectedPeerEntries<()>>,

    services: DataCoreServiceStore,
}

impl DataCore {
    pub async fn new(
        keys: SslKey,
        friends: (Vec<Arc<Peer>>, Vec<Arc<Location>>),
        peer_id: Arc<SslId>,
        gxs_shared_id: Arc<GxsShared>,
        peers_cfg: PeersCfg,
        base_dir: PathBuf,
    ) -> Arc<DataCore> {
        let me = friends
            .1
            .iter()
            .find(|loc| loc.get_location_id() == peer_id)
            .expect("can't find own location!");

        Arc::new({
            let mut dc = DataCore {
                own_key_pair: keys,
                own_location: me.clone(),

                peers: RwLock::new(friends.0),
                locations: RwLock::new(friends.1),

                peers_cfg: Mutex::new(peers_cfg),
                base_dir,
                friends_of_friends: RwLock::new(HashMap::new()),

                event_listener: Mutex::new(vec![]),
                webui_clients: Mutex::new(vec![]),

                // gxs_dbs: gxs.into_iter().map(|g| Mutex::new(g)).collect(),
                // gxs_ids: HashMap::new(),
                connected_peers: Mutex::new(ConnectedPeerEntries::default()),

                // services: RwLock::new(DataCoreServiceStore::default()),
                services: DataCoreServiceStore::new(gxs_shared_id),
            };
            dc.init().await;
            dc
        })
    }

    async fn init(&mut self) {
        // use retroshare_compat::gxs::GxsType::*;

        // for gxs in &self.gxs_dbs {
        //     let locked = gxs.lock().await;
        //     match locked.get_type() {
        //         Id => {
        //             // load all IDs
        //             // TODO make smarter (cache?)
        //             for entry in locked.get_meta() {
        //                 let id = entry.group_id;
        //                 let key = entry.keys;
        //                 self.gxs_ids.insert(id.into(), key);
        //             }
        //         }
        //         Forum => (),
        //     }
        // }
    }

    pub fn get_own_location(&self) -> Arc<Location> {
        self.own_location.clone()
    }

    pub fn get_own_person(&self) -> Arc<Peer> {
        // used stored location for O(1) lookup of own person
        self.own_location.get_person()
    }

    // #[allow(dead_code)]
    pub fn get_own_keypair(&self) -> &SslKey {
        &self.own_key_pair
    }

    pub fn get_locations(&self) -> Vec<Arc<Location>> {
        self.locations.read().expect("lock poisoned").clone()
    }

    pub fn get_location_by_id(&self, ssl_id: Arc<SslId>) -> Option<Arc<Location>> {
        self.get_locations()
            .into_iter()
            .find(|loc| loc.get_location_id() == ssl_id)
    }

    pub fn get_persons(&self) -> Vec<Arc<Peer>> {
        self.peers.read().expect("lock poisoned").clone()
    }

    pub fn get_base_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    /// Person with the given PGP id, if known.
    pub fn get_person_by_pgp_id(&self, pgp_id: &retroshare_compat::basics::PgpId) -> Option<Arc<Peer>> {
        self.get_persons()
            .into_iter()
            .find(|p| p.get_pgp_id() == pgp_id)
    }

    /// Adds a friend location at runtime and saves `peers.cfg`.
    /// `person` may be an existing person (new location of a known friend) or a new one.
    pub async fn add_friend(
        &self,
        person: Arc<Peer>,
        location: Arc<Location>,
        item: retroshare_compat::config::PeerNetItem,
    ) -> std::io::Result<()> {
        {
            let mut peers = self.peers.write().expect("lock poisoned");
            if !peers.iter().any(|p| Arc::ptr_eq(p, &person)) {
                peers.push(person.clone());
            }
        }
        person.add_location(location.clone());
        self.locations
            .write()
            .expect("lock poisoned")
            .push(location);

        let mut cfg = self.peers_cfg.lock().await;
        cfg.add_or_update(item);
        cfg.save(&self.own_key_pair)
    }

    /// Removes a friend's location at runtime, like RetroShare's
    /// `rsPeers::removeFriendLocation()`: disconnects it, forgets it (so it can't
    /// connect again, the listener only accepts known locations) and saves
    /// `peers.cfg`. A person without locations left is removed too. The PGP key stays
    /// in the public keyring, like RetroShare does it.
    pub async fn remove_friend(&self, ssl_id: &SslId) -> Result<String, String> {
        if ssl_id == &*self.own_location.get_location_id() {
            return Err("this is your own location".into());
        }
        let location = self
            .get_location_by_id(Arc::new(*ssl_id))
            .ok_or_else(|| format!("{ssl_id} is not a friend"))?;
        let person = location.get_person();

        self.locations
            .write()
            .expect("lock poisoned")
            .retain(|l| !Arc::ptr_eq(l, &location));
        if person.remove_location(&location) == 0 {
            self.peers
                .write()
                .expect("lock poisoned")
                .retain(|p| !Arc::ptr_eq(p, &person));
        }

        // close the connection, the peer task reports NotConnected when it ends
        if let Some((tx, _)) = self.connected_peers.lock().await.0.get(&Arc::new(*ssl_id)) {
            let _ = tx.send(Intercom::Thread(intercom::PeerThreadCommand::Stop));
        }

        {
            let mut cfg = self.peers_cfg.lock().await;
            cfg.remove(ssl_id);
            cfg.save(&self.own_key_pair)
                .map_err(|err| format!("failed to save peers.cfg: {err}"))?;
        }
        Ok(format!("{} ({})", person.get_name(), location.get_name()))
    }

    /// Updates (or adds) a `peers.cfg` entry and saves the file, e.g. for our own
    /// location's listening address.
    pub async fn update_peers_cfg(
        &self,
        item: retroshare_compat::config::PeerNetItem,
    ) -> std::io::Result<()> {
        let mut cfg = self.peers_cfg.lock().await;
        cfg.add_or_update(item);
        cfg.save(&self.own_key_pair)
    }

    pub fn add_friend_of_friend(&self, ssl_id: SslId, mut fof: FriendOfFriend) {
        let mut map = self.friends_of_friends.write().expect("lock poisoned");
        if let Some(old) = map.get(&ssl_id) {
            for v in &old.via {
                if !fof.via.contains(v) {
                    fof.via.push(v.to_owned());
                }
            }
        }
        map.insert(ssl_id, fof);
    }

    pub fn get_friends_of_friends(&self) -> Vec<FriendOfFriend> {
        let friends: Vec<SslId> = self
            .get_locations()
            .iter()
            .map(|l| *l.get_location_id())
            .collect();
        self.friends_of_friends
            .read()
            .expect("lock poisoned")
            .iter()
            .filter(|(id, _)| !friends.contains(*id))
            .map(|(_, f)| f.to_owned())
            .collect()
    }

    /// The location's `config` folder.
    pub async fn get_config_dir(&self) -> PathBuf {
        self.peers_cfg.lock().await.config_dir()
    }

    /// Our own `peers.cfg` entry, if there is one.
    pub async fn get_own_peers_cfg_item(&self) -> Option<retroshare_compat::config::PeerNetItem> {
        self.peers_cfg
            .lock()
            .await
            .get(&self.own_location.get_location_id())
            .cloned()
    }

    pub async fn events_subscribe(&self, receiver: UnboundedSender<Intercom>) {
        self.event_listener.lock().await.push(receiver);
    }

    pub async fn get_subscribers(&self) -> MutexGuard<'_, Vec<UnboundedSender<Intercom>>> {
        self.event_listener.lock().await
    }

    pub async fn is_online(&self, peer_id: Arc<SslId>) -> bool {
        self.connected_peers.lock().await.0.contains_key(&peer_id)
    }

    pub fn get_connected_peers(&self) -> &Mutex<ConnectedPeerEntries<()>> {
        &self.connected_peers
    }

    pub async fn try_send_to_peer(&self, packet: Packet) {
        // lock peers once

        if packet.has_location() {
            debug!("sending to peer {}", packet.peer_id());
            self.send_to_peer(packet).await;
        } else {
            debug!("sending to <all>");
            for peer in &self.connected_peers.lock().await.0 {
                let mut item = packet.to_owned();
                item.peer_id = peer.0.to_owned();
                peer.1 .0.send(Intercom::Send(item)).unwrap_or_else(|_| {
                    warn!("[core] failed to send to peer worker");
                });
            }
        }
    }

    async fn send_to_peer(&self, packet: Packet) {
        assert!(packet.has_location());

        let to = packet.peer_id.clone();

        self.connected_peers
            .lock()
            .await
            .0
            .entry(to)
            .and_modify(|(tx, _)| {
                tx.send(Intercom::Send(packet)).unwrap_or_else(|_| {
                    warn!("[core] failed to send to peer worker");
                })
            });
    }

    pub async fn webui_add_client(&self, tx: UnboundedSender<Value>) {
        trace!("webui_add_client");

        tx.send(json!({
            "retval":{
                "errorNumber": 0,
                "errorCategory": "generic",
                "errorMessage": "Success"
            }
        }))
        .expect("failed to send");
        self.webui_clients.lock().await.push(tx);
    }

    pub async fn webui_send(&self, event: EventType) {
        trace!("webui_send");

        let msg: Value = event.into();

        let mut ok_clients = Vec::new();
        for client in self.webui_clients.lock().await.iter() {
            let result = client.send(msg.to_owned());

            if let Ok(()) = result {
                ok_clients.push(client.to_owned());
            }
        }
        *self.webui_clients.lock().await = ok_clients;
    }

    pub fn get_service_data(&self) -> &DataCoreServiceStore {
        &self.services
    }
}
