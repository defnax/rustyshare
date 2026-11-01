use std::{
    collections::{HashMap, VecDeque},
    fmt::Debug,
    sync::Arc,
    time::Duration,
};

use log::{debug, trace, warn};
use retroshare_compat::{
    basics::{GxsGroupId, GxsMessageId, PeerId, SslId},
    gxs::{
        sqlite::{
            database::{GxsDatabase, StoredMsg},
            types::{GxsCircleType, GxsGroup, GxsGrpMetaSql, SubscribeFlags},
        },
        NxsSyncGrpItem, NxsTransactionItemType,
    },
};
use tokio::{
    select,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        Mutex, RwLock,
    },
    time::{interval, Interval},
};
#[cfg(feature = "tracing")]
use tracing::event;

use crate::{
    gxs::transaction::StoredNxsItem,
    low_level_parsing::Packet,
    model::{
        gxs_timestamps::GxsSyncTimeStamps, intercom::Intercom, services::AppRequest, DataCore,
    },
    utils::timer_stuff::Timers,
};

use super::{nxs::NxsTransactionController, transaction::TransactionId};

// TODO
/// Wrapper for transporting various gxs/nxs items
#[derive(Debug)]
pub enum GxsItemsWrapper {
    GxsGroupIdsAll,
    GxsGroupIds(Vec<GxsGroupId>),
    /// one group including its data (e.g. an identity's PGP link)
    GxsGroupWithData(GxsGroupId),
    GxsGroups(Vec<GxsGroup>),
    /// request: messages (posts) of a group; answered with `Msgs`
    MsgsOfGroup(GxsGroupId),
    Msgs(Vec<StoredMsg>),
    /// request: subscribe (true) / unsubscribe a group; answered with empty `GxsGroups`
    Subscribe(GxsGroupId, bool),
    /// request: set message status (1 = verified) or delete (-1) after checking
    /// signatures; answered with empty `GxsGroups`
    MsgStatus(Vec<(String, i64)>),
    // GxsMessage(GxsMessageId),
}

// +++++++++++++++++++++++++++++++++++++++++
// +++++++++++++++++++++++++++++++++++++++++
// +++++++++++++++++++++++++++++++++++++++++
#[derive(Debug)]
pub enum GxsTaskData {
    GroupIds(Vec<GxsGroupId>),
    /// a friend's group list (`GRP_LIST_RESP`): group id + publish time
    GroupList(Vec<(GxsGroupId, u32)>),
    /// a friend's message ids (`MSG_LIST_RESP`)
    MsgList(Vec<(GxsGroupId, GxsMessageId)>),
    /// received messages (`MSGS`)
    Msgs(Vec<StoredMsg>),
    Groups(Vec<GxsGroup>),
}

#[derive(Debug, PartialEq)]
pub enum GxsTaskOrigin {
    Own,
    Peer(Arc<PeerId>, u32),
}

#[derive(Debug, PartialEq)]
pub enum GxsTaskState {
    Created,
    Pending(TransactionId),
    Completed,
    Failed,
}
#[derive(Debug)]
pub struct GxsTask {
    pub origin: GxsTaskOrigin,
    pub state: GxsTaskState,

    pub ty: NxsTransactionItemType,
    pub data: Option<GxsTaskData>,
}

impl GxsTask {
    pub fn is_transaction(&self, id: TransactionId) -> bool {
        match self.state {
            GxsTaskState::Pending(transaction_id) => transaction_id == id,
            GxsTaskState::Completed | GxsTaskState::Failed | GxsTaskState::Created => false,
        }
    }
}

// +++++++++++++++++++++++++++++++++++++++++
// +++++++++++++++++++++++++++++++++++++++++
// +++++++++++++++++++++++++++++++++++++++++

enum GxsRequestChannelInner<IN, OUT> {
    Initialized(
        Option<(
            UnboundedSender<AppRequest<IN, OUT>>,
            UnboundedReceiver<AppRequest<IN, OUT>>,
        )>,
    ),
    Ready(UnboundedSender<AppRequest<IN, OUT>>),
}

pub struct GxsRequestChannel<IN, OUT>(RwLock<GxsRequestChannelInner<IN, OUT>>);

impl<IN, OUT> GxsRequestChannel<IN, OUT> {
    pub fn new() -> Self {
        let (tx, rx): (
            UnboundedSender<AppRequest<IN, OUT>>,
            UnboundedReceiver<AppRequest<IN, OUT>>,
        ) = unbounded_channel();
        GxsRequestChannel(RwLock::new(GxsRequestChannelInner::Initialized(Some((
            tx, rx,
        )))))
    }

    pub fn take_receiver(&self) -> UnboundedReceiver<AppRequest<IN, OUT>> {
        let mut lock = self.0.try_write().unwrap(); // when this is called, there should only be one writer (the caller)
        let (tx, rx) = match *lock {
            GxsRequestChannelInner::Initialized(ref mut inner) => inner.take().unwrap(),
            GxsRequestChannelInner::Ready(_) => panic!("calling take_receiver twice it a bug!"),
        };
        *lock = GxsRequestChannelInner::Ready(tx);

        rx
    }

    pub fn add_request(&self, request: AppRequest<IN, OUT>)
    where
        IN: Debug,
        OUT: Debug,
    {
        match *self.0.try_read().unwrap() {
            // when this is called there should only be readers but not a single writer anymore
            // a failed send means the GXS service stopped; the caller's request then
            // simply times out instead of taking the web UI / chat service down too
            GxsRequestChannelInner::Ready(ref tx) => {
                if tx.send(request).is_err() {
                    log::error!("GXS service is not running anymore, request dropped");
                }
            }
            GxsRequestChannelInner::Initialized(Some(ref inner)) => {
                log::error!("add_request was called before take_receiver!");
                if inner.0.send(request).is_err() {
                    log::error!("GXS service is not running anymore, request dropped");
                }
            }
            _ => panic!(),
        }
    }
}

// Object shared between various gxs/nxs components
pub struct GxsShared {
    pub(super) core_tx: UnboundedSender<Intercom>,

    pub(super) own_id: Arc<SslId>,

    pub(super) gxs_timestamps: GxsSyncTimeStamps,

    // queues
    // received_items: Mutex<VecDeque<GxsItemsWrapper>>,
    pub requests: GxsRequestChannel<GxsItemsWrapper, GxsItemsWrapper>,
}

impl GxsShared {
    pub fn new(core_tx: UnboundedSender<Intercom>, own_id: Arc<SslId>) -> Self {
        GxsShared {
            core_tx,
            own_id,
            gxs_timestamps: GxsSyncTimeStamps::new(),

            // received_items: Mutex::new(VecDeque::new()),
            // requests: Mutex::new(Vec::new()),
            requests: GxsRequestChannel::new(),
        }
    }
}

pub struct GxsBackend<const TYPE: u16> {
    core: Arc<DataCore>,

    shared: Arc<GxsShared>,
    requests: UnboundedReceiver<AppRequest<GxsItemsWrapper, GxsItemsWrapper>>,

    database: Mutex<GxsDatabase>,
    mem_cache: Mutex<GxsDatabase>,
    nxs: NxsTransactionController<TYPE>,

    tasks: Mutex<Vec<GxsTask>>,

    missing_groups: Mutex<Vec<(GxsGroupId, Arc<PeerId>)>>,

    timer: Interval,
    timer_sync_server_ts: Interval,
    timer_sync_groups: Interval,
    timer_load_missing: Interval,

    /// stored identities were checked (once per start)
    stored_checked: bool,

    /// (friend, group) -> update time of the newest message list we got from it
    msg_sync_ts: Mutex<HashMap<(Arc<PeerId>, GxsGroupId), u32>>,

    /// message requests still to send (friend, group, up to 20 message ids). Big
    /// forums need hundreds of them; they are sent a few at a time, and keeping them
    /// here means nothing is lost when the backend loop restarts.
    msg_request_queue: Mutex<VecDeque<(Arc<PeerId>, GxsGroupId, Vec<GxsMessageId>)>>,
}

impl<const TYPE: u16> Debug for GxsBackend<TYPE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tasks {:?}, missing: {:?}",
            self.tasks.blocking_lock().len(),
            self.missing_groups.blocking_lock().len()
        )
    }
}

impl<const TYPE: u16> GxsBackend<TYPE> {
    pub fn new(
        core: Arc<DataCore>,
        db: GxsDatabase,
        nxs: NxsTransactionController<TYPE>,
        shared: Arc<GxsShared>,
    ) -> Self {
        // setup mem cache
        let mem_cache = GxsDatabase::new_mem("").unwrap();
        // let mem_cache = GxsDatabase::new_file("/tmp/foo.db".into(), "").unwrap();

        let requests = shared.requests.take_receiver();

        Self {
            core,

            shared,
            requests,

            database: Mutex::new(db),
            mem_cache: Mutex::new(mem_cache),
            nxs,

            tasks: Mutex::new(vec![]),

            missing_groups: Mutex::new(vec![]),

            timer: interval(Duration::from_millis(25)),
            timer_sync_server_ts: interval(Duration::from_secs(120)),
            timer_sync_groups: interval(Duration::from_secs(60)),
            timer_load_missing: interval(Duration::from_secs(3)),

            stored_checked: false,
            msg_sync_ts: Mutex::new(HashMap::new()),
            msg_request_queue: Mutex::new(VecDeque::new()),
        }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub async fn get_group(&self, group_id: &GxsGroupId, with_data: bool) -> Option<GxsGroup> {
        trace!("getting group {group_id}");
        // FIXME this code is a bit odd since the database is not Send. Therefore we cannot hold any reference across an `await`

        let res = match self.mem_cache.lock().await.get_grp_meta(group_id) {
            Ok(Some(group)) => {
                trace!("found group in mem_cache");
                Some(group)
            }
            Ok(None) => None,
            Err(err) => {
                debug!("failed to get group by id: {err}");
                None
            }
        };

        if let Some(mut group) = res {
            #[cfg(feature = "tracing")]
            event!(tracing::Level::DEBUG, "found in memcache");
            if with_data {
                self.mem_cache
                    .lock()
                    .await
                    .get_grp_data(&mut group)
                    .unwrap();
            }
            return Some(group);
        }
        #[cfg(feature = "tracing")]
        event!(tracing::Level::DEBUG, "nothing in memcache");

        let res = match self.database.lock().await.get_grp_meta(group_id) {
            Ok(result) => result,
            Err(err) => {
                debug!("failed to get group by id: {err}");

                None
            }
        };

        match res {
            None => {
                #[cfg(feature = "tracing")]
                event!(tracing::Level::DEBUG, "nothing in database");

                self.missing_groups
                    .lock()
                    .await
                    .push((group_id.to_owned(), Arc::new(PeerId::default())));
                None
            }
            Some(mut group) => {
                trace!("found group in database");
                #[cfg(feature = "tracing")]
                event!(tracing::Level::DEBUG, "found in database");

                let found = self.database.lock().await.get_grp_data(&mut group).is_ok();

                if found {
                    if let Err(err) = self.mem_cache.lock().await.insert_group(&group) {
                        warn!("failed to cache group {}: {err}", group.group_id);
                    }
                }

                Some(group)
            }
        }
    }

    async fn request_groups(&self) {
        // collect ids per peer
        let mut peer_map: HashMap<Arc<PeerId>, Vec<GxsGroupId>> = HashMap::new();

        let missing: Vec<_> = self.missing_groups.lock().await.drain(..).collect();
        if missing.is_empty() {
            return;
        }

        // groups without a known source (e.g. the identity of someone talking in a chat
        // lobby) are asked from all connected friends; before they were sent to an
        // empty peer id and never left rustyshare
        let connected: Vec<Arc<PeerId>> = self
            .core
            .get_connected_peers()
            .lock()
            .await
            .0
            .keys()
            .cloned()
            .collect();

        for (group, peer) in missing {
            if peer.is_default() {
                for p in &connected {
                    peer_map.entry(p.clone()).or_default().push(group);
                }
            } else {
                peer_map.entry(peer).or_default().push(group);
            }
        }

        for (peer_id, mut group_ids) in peer_map {
            group_ids.sort();
            group_ids.dedup();
            debug!("requesting {} missing groups from {peer_id}", group_ids.len());
            let transaction_id = self.nxs.request_groups(&group_ids, peer_id).await;

            let task = GxsTask {
                origin: GxsTaskOrigin::Own,
                state: GxsTaskState::Pending(transaction_id),
                data: None,
                ty: NxsTransactionItemType::Groups,
            };

            self.tasks.lock().await.push(task);
        }
    }

    async fn handle_tasks(&self) {
        let mut lock = self.tasks.lock().await;

        self.nxs.handle_completed_transactions(&mut lock).await;

        for task in lock.iter_mut() {
            // debug!("{task:?}");
            match &task.origin {
                GxsTaskOrigin::Own => {
                    // self initiated tasks
                    match &task.state {
                        GxsTaskState::Completed => match &task.ty {
                            NxsTransactionItemType::Groups => {
                                // we requested groups and received groups

                                // process and add groups
                                let groups =
                                    match task.data.take().expect(
                                        "expected groups but nothing is set, this is a bug!",
                                    ) {
                                        GxsTaskData::Groups(groups) => groups,
                                        data @ _ => panic!("unexpected task data {data:?}"),
                                    };

                                for group in groups {
                                    debug!("adding groups {}", group.group_id);

                                    // check the admin signature like RetroShare does for
                                    // every group (identities, forums, ...) and drop
                                    // the ones that fail
                                    if let Err(err) = crate::gxs::create_id::check_group_signature(&group) {
                                        log::warn!(
                                            "rejected group '{}' ({}) of service {TYPE:#06x}: {err}",
                                            group.group_name,
                                            group.group_id
                                        );
                                        continue;
                                    }

                                    // keep received groups (e.g. friends' identities)
                                    // in the database, so they survive a restart and
                                    // don't have to be fetched again. Groups we already
                                    // have (above all our own, with private keys) are
                                    // never overwritten by a copy from a friend.
                                    {
                                        let db = self.database.lock().await;
                                        match db.get_grp_meta(&group.group_id) {
                                            Ok(Some(_)) => {}
                                            Ok(None) => {
                                                if let Err(err) = db.insert_group(&group) {
                                                    warn!(
                                                        "failed to save received group {}: {err}",
                                                        group.group_id
                                                    );
                                                }
                                            }
                                            Err(err) => warn!(
                                                "failed to look up group {}: {err}",
                                                group.group_id
                                            ),
                                        }
                                    }

                                    if let Err(err) =
                                        self.mem_cache.lock().await.insert_group(&group)
                                    {
                                        warn!(
                                            "failed to store received group {}: {err}",
                                            group.group_id
                                        );
                                    }
                                }

                                //     // validate group
                                //     // TODO
                                //     /*
                                //     uint32_t p3IdService::idAuthenPolicy()
                                //     {
                                //         uint32_t policy = 0;
                                //         uint8_t flag = 0;

                                //         // Messages are send reputations. normally not by ID holder - so need signatures.
                                //         flag = GXS_SERV::MSG_AUTHEN_ROOT_AUTHOR_SIGN | GXS_SERV::MSG_AUTHEN_CHILD_AUTHOR_SIGN;
                                //         RsGenExchange::setAuthenPolicyFlag(flag, policy, RsGenExchange::PUBLIC_GRP_BITS);
                                //         RsGenExchange::setAuthenPolicyFlag(flag, policy, RsGenExchange::RESTRICTED_GRP_BITS);
                                //         RsGenExchange::setAuthenPolicyFlag(flag, policy, RsGenExchange::PRIVATE_GRP_BITS);

                                //         // No ID required.
                                //         flag = 0;
                                //         RsGenExchange::setAuthenPolicyFlag(flag, policy, RsGenExchange::GRP_OPTION_BITS);

                                //         return policy;
                                //     }
                                //     */
                                //     const POLICY: u32 = 0x000c0c0c;
                                //     let check_authen_flags = |policy: u32| -> bool { (0x01 & (policy >> 24)) > 0 };
                                //     if meta.author_id != GxsId::default() && check_authen_flags(POLICY) {}

                                //     // compute hash
                                //     // TODO verify code
                                //     {
                                //         let hash =
                                //             openssl::hash::hash(openssl::hash::MessageDigest::sha1(), &group.grp).unwrap();
                                //         meta.hash = hash.as_ref().to_owned().into();
                                //     }

                                //     // TODO?
                                //     group.meta_data = Some(meta.to_owned());
                            }
                            _ => {
                                warn!("unimplemented task {task:?} please fix!");
                            }
                        },
                        GxsTaskState::Created => {
                            unimplemented!()
                        }
                        GxsTaskState::Failed => {
                            // TODO?
                        }
                        GxsTaskState::Pending(_transaction_id) => {}
                    }
                }
                GxsTaskOrigin::Peer(peer_id, ts) => {
                    // peer initiated tasks
                    match &task.state {
                        GxsTaskState::Completed => {
                            match &task.ty {
                                NxsTransactionItemType::MessageListResponse => {
                                    // message ids of a group the friend has
                                    // (locked_genReqMsgTransaction): ask for the new ones
                                    let list = match task.data.take() {
                                        Some(GxsTaskData::MsgList(list)) => list,
                                        _ => vec![],
                                    };
                                    // Note: no `await` inside the loops below. This code runs
                                    // inside the backend loop, which is restarted for every
                                    // incoming packet; with big forums (thousands of ids) an
                                    // await per id meant the work was cancelled half way and
                                    // the list lost, so big forums never got their posts.
                                    let mut wanted: HashMap<GxsGroupId, Vec<GxsMessageId>> = HashMap::new();
                                    let mut groups = vec![];
                                    {
                                        let db = self.database.lock().await;
                                        for (group_id, msg_id) in list {
                                            if !groups.contains(&group_id) {
                                                groups.push(group_id);
                                            }
                                            if !db.has_message(&msg_id.to_string()).unwrap_or(false) {
                                                wanted.entry(group_id).or_default().push(msg_id);
                                            }
                                        }
                                    }
                                    if wanted.is_empty() {
                                        let mut map = self.msg_sync_ts.lock().await;
                                        for group_id in groups {
                                            map.insert((peer_id.to_owned(), group_id), *ts);
                                        }
                                    } else {
                                        let mut queue = self.msg_request_queue.lock().await;
                                        for (group_id, ids) in wanted {
                                            // skip ids that are already waiting to be requested
                                            let queued: std::collections::HashSet<GxsMessageId> = queue
                                                .iter()
                                                .filter(|(p, g, _)| p == peer_id && *g == group_id)
                                                .flat_map(|(_, _, ids)| ids.iter().copied())
                                                .collect();
                                            let ids: Vec<_> = ids.into_iter().filter(|id| !queued.contains(id)).collect();
                                            if ids.is_empty() {
                                                continue;
                                            }
                                            debug!("{peer_id} has {} new messages in {group_id}", ids.len());
                                            // RetroShare limits the size of request lists (MAX_REQLIST_SIZE)
                                            for chunk in ids.chunks(20) {
                                                queue.push_back((peer_id.to_owned(), group_id, chunk.to_vec()));
                                            }
                                        }
                                    }
                                    task.state = GxsTaskState::Failed; // done, remove
                                }
                                NxsTransactionItemType::Messages => {
                                    // received messages: store them; signatures are checked
                                    // when they are shown (the author identity may still
                                    // have to be fetched)
                                    let msgs = match task.data.take() {
                                        Some(GxsTaskData::Msgs(msgs)) => msgs,
                                        _ => vec![],
                                    };
                                    let db = self.database.lock().await;
                                    let mut stored = 0;
                                    for msg in &msgs {
                                        match db.insert_message_raw(msg) {
                                            Ok(()) => stored += 1,
                                            Err(err) => warn!("failed to store message {}: {err}", msg.msg_id),
                                        }
                                    }
                                    drop(db);
                                    if stored > 0 {
                                        log::info!("stored {stored} new messages (service {TYPE:#06x})");
                                    }
                                    task.state = GxsTaskState::Failed; // done, remove
                                }
                                NxsTransactionItemType::GroupListResponse => {
                                    // the friend told us which groups it has
                                    // (locked_genReqGrpTransaction): ask for the ones we
                                    // don't have or that are newer
                                    let list = match task.data.take() {
                                        Some(GxsTaskData::GroupList(list)) => list,
                                        _ => vec![],
                                    };
                                    let mut wanted = vec![];
                                    for (group_id, publish_ts) in list {
                                        // (no database lock may be held across an await)
                                        let cached = self.mem_cache.lock().await.get_grp_meta(&group_id).ok().flatten();
                                        let local = match cached {
                                            Some(g) => Some(g),
                                            None => self.database.lock().await.get_grp_meta(&group_id).ok().flatten(),
                                        };
                                        match local {
                                            Some(g) if g.publish_ts >= publish_ts as i64 => {}
                                            _ => wanted.push(group_id),
                                        }
                                    }
                                    if wanted.is_empty() {
                                        // nothing new: remember how far we are with this friend
                                        self.shared.gxs_timestamps.update_peer_group(peer_id.to_owned(), *ts).await;
                                        task.state = GxsTaskState::Failed; // done, remove
                                    } else {
                                        debug!("{peer_id} has {} groups we don't have (service {TYPE:#06x})", wanted.len());
                                        let transaction_id = self.nxs.request_groups(&wanted, peer_id.to_owned()).await;
                                        // the answer (Groups) comes as a new transaction; this
                                        // task waits for our request to be confirmed
                                        task.state = GxsTaskState::Pending(transaction_id);
                                    }
                                }
                                NxsTransactionItemType::GroupListRequest => {
                                    // peer requested ids and we will respond now

                                    // 1. collect group ids
                                    let requested_group_ids = match task.data.take().expect(
                                        "expected group ids but nothing is set, this is a bug!",
                                    ) {
                                        GxsTaskData::GroupIds(ids) => ids,
                                        data @ _ => panic!("unexpected task data {data:?}"),
                                    };

                                    debug!(
                                        "peer {peer_id} requested {} groups",
                                        requested_group_ids.len()
                                    );
                                    trace!("{requested_group_ids:?}");

                                    // 2. fetch groups
                                    let items = {
                                        // this is a workaround until async closures are stable
                                        let mut items = vec![];

                                        for group_id in &requested_group_ids {
                                            let res = self.get_group(&group_id, true).await;
                                            trace!("{group_id} -> {res:?}");
                                            match res {
                                                Some(group) => {
                                                    items.push(StoredNxsItem::NxsGrp(group.into()))
                                                }
                                                None => {}
                                            }
                                        }

                                        items
                                    };
                                    trace!("{items:?}");
                                    let empty = items.is_empty();

                                    // 3. send groups to peer (even empty ones, nxs will take care (and especially update timestamps!))
                                    match self
                                        .nxs
                                        .send_groups_transaction(peer_id.to_owned(), *ts, items)
                                        .await
                                    {
                                        Some(transaction_id) => {
                                            task.state = GxsTaskState::Pending(transaction_id);
                                        }
                                        None => {
                                            if empty {
                                                // This is expected on empty groups
                                                debug!("failed to create transaction for {task:?}, no local groups found");
                                            } else {
                                                warn!("failed to create transaction for {task:?}");
                                            }
                                            debug!("requested group ids: {requested_group_ids:?}");
                                            task.state = GxsTaskState::Failed;
                                        }
                                    }
                                }

                                _ => {
                                    warn!("unimplemented task {task:?} please fix!");
                                }
                            }
                        }
                        GxsTaskState::Created => match &task.ty {
                            // GxsPeerRequest::GroupSync(_item) => {
                            NxsTransactionItemType::GroupListResponse => {
                                // peer requested a group item sync
                                // (and nxs timestamps says that there might be something new)

                                // TODO merge once only one db is used.
                                let mut groups: HashMap<GxsGroupId, GxsGrpMetaSql> = HashMap::new();
                                self.database
                                    .lock()
                                    .await
                                    .get_grp_meta_all()
                                    .unwrap()
                                    .into_iter()
                                    .for_each(|group| {
                                        // let _ = groups.insert(group_id);
                                        if !groups.contains_key(&group.group_id) {
                                            groups.insert(group.group_id, group);
                                        }
                                    });
                                self.mem_cache
                                    .lock()
                                    .await
                                    .get_grp_meta_all()
                                    .unwrap()
                                    .into_iter()
                                    .for_each(|group| {
                                        // let _ = groups.insert(group_id);
                                        if !groups.contains_key(&group.group_id) {
                                            groups.insert(group.group_id, group);
                                        }
                                    });

                                let items: Vec<_> = groups
                                    .into_iter()
                                    .map(|(_, group)| GxsGroup::from(group))
                                    .filter(|group| {
                                        true //  group.publish_ts > item.update_ts as i64 // TODO implement all RS checks from RsGxsNetService::canSendGrpId
                                        && group.subscribe_flags.contains(SubscribeFlags::SUBSCRIBED)
                                       &&
                                            [GxsCircleType::Unknown, GxsCircleType::Public]
                                                .contains(&group.circle_type)
                                    })
                                    .map(|group| NxsSyncGrpItem::from(group))
                                    .collect();

                                match self
                                    .nxs
                                    .send_group_sync_transaction(items, peer_id.to_owned())
                                    .await
                                {
                                    Some(transaction_id) => {
                                        task.state = GxsTaskState::Pending(transaction_id)
                                    }
                                    None => {
                                        warn!("failed to create transaction for {task:?}");
                                    }
                                }
                            }
                            _ => {
                                warn!("unimplemented task {task:?} please fix!");
                            }
                        },
                        GxsTaskState::Failed => {
                            // TODO?
                        }
                        GxsTaskState::Pending(_transaction_id) => {}
                    }
                }
            }
        }

        // now remove finished tasks
        lock.retain(|task| match task.state {
            GxsTaskState::Completed | GxsTaskState::Failed => false,
            GxsTaskState::Pending(_) | GxsTaskState::Created => true,
        });
    }

    async fn sync_server_ts(&self) {
        let mut times: Vec<i64> = self
            .database
            .lock()
            .await
            .get_grp_meta_all()
            .unwrap()
            .into_iter()
            .map(|group| group.recv_ts)
            .collect();
        times.sort_unstable();

        if let Some(last) = times.last() {
            self.shared
                .gxs_timestamps
                .update_local_last(*last as u32)
                .await;
        }
    }

    pub async fn handle_packet(&self, packet: Packet) {
        // let peer_id = packet.peer_id.to_owned();

        let mut new_tasks = self
            .nxs
            .handle_incoming_packet(&packet.header.into(), packet)
            .await;

        // register new tasks
        self.tasks.lock().await.append(&mut new_tasks);
    }

    async fn handle_request(&self, request: AppRequest<GxsItemsWrapper, GxsItemsWrapper>) {
        trace!("handling request {request:?}");

        let resp = match request.ty {
            GxsItemsWrapper::MsgsOfGroup(group_id) => {
                let msgs = self
                    .database
                    .lock()
                    .await
                    .get_messages_raw(&group_id.to_string())
                    .unwrap_or_default();
                request
                    .tx
                    .send(GxsItemsWrapper::Msgs(msgs))
                    .unwrap_or_else(|_| warn!("request failed to send, probably timed out"));
                return;
            }
            GxsItemsWrapper::Subscribe(group_id, subscribe) => {
                let id = group_id.to_string();
                let current = self.get_group(&group_id, false).await.map(|g| g.subscribe_flags);
                if let Some(mut flags) = current {
                    flags.remove(SubscribeFlags::SUBSCRIBED | SubscribeFlags::NOT_SUBSCRIBED);
                    flags.insert(if subscribe { SubscribeFlags::SUBSCRIBED } else { SubscribeFlags::NOT_SUBSCRIBED });
                    for db in [&self.database, &self.mem_cache] {
                        if let Err(err) = db.lock().await.set_group_subscribe_flags(&id, flags.bits()) {
                            warn!("failed to change subscription of {id}: {err}");
                        }
                    }
                    log::info!("{} group {id}", if subscribe { "subscribed to" } else { "unsubscribed from" });
                    if subscribe {
                        // fetch its posts right away instead of waiting for the timer
                        let peers: Vec<_> = self.core.get_connected_peers().lock().await.0.keys().cloned().collect();
                        for peer in peers {
                            self.nxs.request_message_sync(peer, group_id, 0);
                        }
                    }
                }
                vec![]
            }
            GxsItemsWrapper::MsgStatus(list) => {
                let db = self.database.lock().await;
                for (msg_id, status) in list {
                    let res = if status < 0 {
                        db.delete_message(&msg_id)
                    } else {
                        db.set_message_status(&msg_id, status)
                    };
                    if let Err(err) = res {
                        warn!("failed to update message {msg_id}: {err}");
                    }
                }
                vec![]
            }
            GxsItemsWrapper::Msgs(_) => vec![],
            GxsItemsWrapper::GxsGroupIds(group_ids) => {
                let mut groups = vec![];
                for group_id in group_ids {
                    match self.get_group(&group_id, false).await {
                        Some(group) => groups.push(group),
                        None => {}
                    }
                }
                groups
            }
            GxsItemsWrapper::GxsGroupWithData(group_id) => {
                self.get_group(&group_id, true).await.into_iter().collect()
            }
            GxsItemsWrapper::GxsGroupIdsAll => {
                // get all ids
                // FIXME once only one db is used
                let mut group_ids = self.database.lock().await.get_group_ids().unwrap();
                for group_id in self.mem_cache.lock().await.get_group_ids().unwrap() {
                    if !group_ids.contains(&group_id) {
                        group_ids.push(group_id);
                    }
                }

                let mut groups = vec![];
                for group_id in group_ids {
                    match self.get_group(&group_id, false).await {
                        Some(group) => groups.push(group),
                        None => {}
                    }
                }
                groups
            }
            // store own new groups (e.g. a freshly created identity) permanently
            GxsItemsWrapper::GxsGroups(groups) => {
                let mut stored = vec![];
                for group in groups {
                    let res = self.database.lock().await.insert_group(&group);
                    match res {
                        Ok(()) => {
                            if let Err(err) = self.mem_cache.lock().await.insert_group(&group) {
                                debug!("failed to cache new group: {err}");
                            }
                            log::info!("stored new group {} ({})", group.group_name, group.group_id);
                            // let friends know we have something new
                            self.shared
                                .gxs_timestamps
                                .update_local_last(group.recv_ts as u32)
                                .await;
                            stored.push(group);
                        }
                        Err(err) => log::error!("failed to store new group {}: {err}", group.group_id),
                    }
                }
                stored
            }
        };

        request
            .tx
            .send(GxsItemsWrapper::GxsGroups(resp))
            .unwrap_or_else(|ref _result| warn!("request failed to send, probably timed out"));
    }

    pub async fn tick(&self, timers: &mut Timers) {
        self.nxs.tick(timers).await;
        self.handle_tasks().await;
    }

    /// Sends a few of the queued message requests (every 3 s), so a big forum doesn't
    /// start hundreds of transactions at once.
    async fn send_queued_msg_requests(&self) {
        const PER_ROUND: usize = 10;
        let batch: Vec<_> = {
            let mut queue = self.msg_request_queue.lock().await;
            let n = queue.len().min(PER_ROUND);
            queue.drain(..n).collect()
        };
        if batch.is_empty() {
            return;
        }
        let left = self.msg_request_queue.lock().await.len();
        debug!("requesting {} message batches, {left} left", batch.len());
        for (peer, group_id, ids) in batch {
            self.nxs.request_messages(group_id, &ids, peer).await;
        }
    }

    /// Asks friends for new messages of the groups we are subscribed to
    /// (RsGxsNetService::syncWithPeers, message part).
    async fn sync_messages(&self, peers: Vec<Arc<PeerId>>) {
        if peers.is_empty() {
            return;
        }
        let subscribed: Vec<GxsGroupId> = {
            let db = self.database.lock().await;
            db.get_grp_meta_all()
                .unwrap_or_default()
                .into_iter()
                .filter(|g| g.subscribe_flags.intersects(SubscribeFlags::SUBSCRIBED | SubscribeFlags::ADMIN))
                .map(|g| g.group_id)
                .collect()
        };
        let busy: Vec<(Arc<PeerId>, GxsGroupId)> = self
            .msg_request_queue
            .lock()
            .await
            .iter()
            .map(|(p, g, _)| (p.to_owned(), *g))
            .collect();
        for group_id in subscribed {
            for peer in &peers {
                // still downloading this forum from this friend: ask again when done
                if busy.contains(&(peer.to_owned(), group_id)) {
                    continue;
                }
                let ts = self
                    .msg_sync_ts
                    .lock()
                    .await
                    .get(&(peer.to_owned(), group_id))
                    .copied()
                    .unwrap_or(0);
                self.nxs.request_message_sync(peer.to_owned(), group_id, ts);
            }
        }
    }

    /// Checks the signatures of all stored identities once at startup and logs the
    /// ones that fail (RetroShare re-validates stored groups as well).
    async fn check_stored_identities(&self) {
        use crate::gxs::create_id::check_group_signature;

        let db = self.database.lock().await;
        let ids = match db.get_group_ids() {
            Ok(ids) => ids,
            Err(err) => return warn!("can't list stored identities: {err}"),
        };
        let (mut ok, mut invalid) = (0, 0);
        for id in ids {
            let Ok(Some(mut group)) = db.get_grp_meta(&id) else { continue };
            if db.get_grp_data(&mut group).is_err() {
                continue;
            }
            match check_group_signature(&group) {
                Ok(()) => ok += 1,
                Err(err) => {
                    invalid += 1;
                    warn!(
                        "stored identity '{}' ({}) fails the signature check: {err}",
                        group.group_name, group.group_id
                    );
                }
            }
        }
        log::info!("checked stored identities: {ok} OK, {invalid} invalid");
    }

    pub async fn run(&mut self) {
        // run() is restarted by the service loop for every packet: check only once
        if TYPE == retroshare_compat::services::SERVICE_GXS_GXSID && !self.stored_checked {
            self.stored_checked = true;
            self.check_stored_identities().await;
        }

        // all of these must be restartable!
        loop {
            select! {
                request = self.requests.recv() => {
                    if let Some(request) = request {
                        self.handle_request(request).await;
                    }
                }
                _ = self.timer.tick() => {
                    let mut dummy = Timers::new();
                    self.tick(&mut dummy).await;
                }
                _ = self.timer_sync_server_ts.tick() => {
                    trace!("sync_server_ts");
                    self.sync_server_ts().await;
                }
                _ = self.timer_sync_groups.tick() => {
                    // like RetroShare: identities are not auto synced (grpAutoSync = false
                    // for gxsid), they are fetched when needed; forums etc. are
                    if TYPE != retroshare_compat::services::SERVICE_GXS_GXSID {
                        trace!("check_peer_updates");
                        let peers: Vec<_> = self.core.get_connected_peers().lock().await.0.iter().map(|(peer, _)| peer.to_owned()).collect();
                        self.nxs.check_peer_updates(peers.clone()).await;
                        self.sync_messages(peers).await;
                    }
                }
                _ = self.timer_load_missing.tick() => {
                    trace!("requesting missing");
                    self.request_groups().await;
                    self.send_queued_msg_requests().await;
                }
            }
        }
    }
}
